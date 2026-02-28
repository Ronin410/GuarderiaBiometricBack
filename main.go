package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rekognition"
	"github.com/aws/aws-sdk-go-v2/service/rekognition/types"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

var db *sql.DB
var dbAuth *sql.DB
var rekClient *rekognition.Client
var jwtKey = []byte("tu_clave_secreta_super_segura") // Cambiar por variable de entorno

func getCollectionID(guarderiaID any) string {
	return fmt.Sprintf("guarderia-%v", guarderiaID)
	//return fmt.Sprintf("guarderia-rostros")
}

type PinRequest struct {
	Pin string `json:"pin"`
}

type Claims struct {
	UserID      int    `json:"user_id"`
	GuarderiaID int    `json:"guarderia_id"`
	Rol         string `json:"rol"`
	jwt.RegisteredClaims
}

// Estructuras para la respuesta enriquecida
type Hijo struct {
	ID           int    `json:"id"`
	Nombre       string `json:"nombre"`
	UltimoEstado string `json:"ultimo_estado"` // Nuevo campo
	Activo       bool   `json:"activo"`
}

type RespuestaIdentificacion struct {
	PadreID   int     `json:"padre_id"`
	Padre     string  `json:"padre"`
	Confianza float64 `json:"confianza"`
	Hijos     []Hijo  `json:"hijos"`
	Mensaje   string  `json:"mensaje"`
}

type RegistroAsistencia struct {
	PadreID       int    `json:"padre_id"`
	HijoID        int    `json:"hijo_id"`
	Aseado        bool   `json:"aseado"`
	ReporteGolpe  bool   `json:"reporte_golpe"`
	Observaciones string `json:"observaciones"`
	Tipo          string `json:"tipo"` // "ENTRADA" o "SALIDA"
}

type VinculacionRequest struct {
	PadreID int `json:"padre_id"`
	HijoID  int `json:"hijo_id"`
}

type ReporteData struct {
	Fecha         string `json:"fecha"`
	HijoNombre    string `json:"hijo_nombre"`
	TutorNombre   string `json:"tutor_nombre"` // <-- Nuevo campo
	Tipo          string `json:"tipo"`
	Aseado        bool   `json:"aseado"`
	ReporteGolpe  bool   `json:"reporte_golpe"`
	Observaciones string `json:"observaciones"`
}

func init() {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		log.Fatal("ERROR: Credenciales de AWS no configuradas.")
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(os.Getenv("AWS_REGION")),
	)
	if err != nil {
		log.Fatalf("No se pudo cargar la configuración de AWS: %v", err)
	}

	rekClient = rekognition.NewFromConfig(cfg)

	dsnAuth := os.Getenv("DATABASE_URL_AUTH") // ej: postgres://user:pass@localhost:5432/db_auth
	dbAuth, err = sql.Open("postgres", dsnAuth)
	if err != nil || dbAuth.Ping() != nil {
		log.Fatal("Error conectando a DB Auth")
	}

	connStr := os.Getenv("DATABASE_URL")
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	RunMigrations()

	if err = db.Ping(); err != nil {
		log.Fatal("No se pudo conectar a la DB:", err)
	}
	fmt.Println("Conexión a Postgres exitosa")
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. IMPORTANTE: El pre-vuelo de CORS (OPTIONS) no debe validar el Token
		//if c.Request.Method == "OPTIONS" {
		//	c.AbortWithStatus(http.StatusNoContent)
		//	return
		//}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token requerido"})
			c.Abort() // Detiene la ejecución aquí
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token inválido o expirado"})
			c.Abort()
			return
		}

		c.Set("guarderia_id", claims.GuarderiaID)
		c.Set("user_id", claims.UserID)
		c.Set("rol", claims.Rol)
		c.Next()
	}
}

func main() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		// Agregamos ambas variantes de localhost para evitar conflictos
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "X-Guarderia-Slug"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.POST("/login", func(c *gin.Context) {
		// 1. Estructura para recibir datos de Postman
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		// Validar formato JSON
		if err := c.ShouldBindJSON(&creds); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "JSON inválido"})
			return
		}

		// LOG de depuración
		fmt.Printf("Intentando login plano: Usuario[%s] Pass[%s]\n", creds.Username, creds.Password)

		var id, gID int
		var passHash, rol, pin string

		// 2. Consulta a la base de datos
		query := `
		SELECT id, guarderia_id, password_hash, rol, pin_admin 
		FROM usuarios 
		WHERE username = $1`

		err := dbAuth.QueryRow(query, creds.Username).Scan(&id, &gID, &passHash, &rol, &pin)
		if err != nil {
			if err == sql.ErrNoRows {
				fmt.Printf("Usuario no encontrado: %s\n", creds.Username)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Usuario no existe"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error de BD"})
			}
			return
		}

		// 3. COMPARACIÓN EN TEXTO PLANO (MODIFICADO)
		// Usamos strings.TrimSpace para evitar errores por espacios invisibles en la DB
		if strings.TrimSpace(passHash) != strings.TrimSpace(creds.Password) {
			fmt.Printf("FALLO: La clave en DB [%s] no coincide con [%s]\n", passHash, creds.Password)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Contraseña incorrecta"})
			return
		}

		// 4. Generación del Token JWT (Se mantiene igual)
		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			UserID:      id,
			GuarderiaID: gID,
			Rol:         rol,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al generar token"})
			return
		}

		// 5. Respuesta Exitosa
		fmt.Printf("Login exitoso (Texto Plano): %s\n", creds.Username)
		c.JSON(http.StatusOK, gin.H{
			"token":        tokenStr,
			"guarderia_id": gID,
			"rol":          rol,
			"username":     creds.Username,
			"pin_admin":    pin,
		})
	})

	// --- ENDPOINT REGISTRAR ---
	r.POST("/registrar", AuthMiddleware(), func(c *gin.Context) {
		gID, _ := c.Get("guarderia_id")
		colID := getCollectionID(gID) // <-- Colección específica

		var input struct {
			Nombre string `json:"nombre"`
			Imagen string `json:"imagen"`
		}
		c.BindJSON(&input)
		imgBytes, _ := base64.StdEncoding.DecodeString(input.Imagen)

		// 1. Validar duplicados SOLO en la colección de esta guardería
		searchRes, err := rekClient.SearchFacesByImage(context.TODO(), &rekognition.SearchFacesByImageInput{
			CollectionId:       aws.String(colID),
			FaceMatchThreshold: aws.Float32(90.0),
			Image:              &types.Image{Bytes: imgBytes},
			MaxFaces:           aws.Int32(1),
		})

		if err == nil && len(searchRes.FaceMatches) > 0 {
			c.JSON(409, gin.H{"error": "Esta persona ya está registrada en esta guardería."})
			return
		}

		// 2. Registro en la colección específica
		indexRes, err := rekClient.IndexFaces(context.TODO(), &rekognition.IndexFacesInput{
			CollectionId:    aws.String(colID),
			ExternalImageId: aws.String(strings.ReplaceAll(input.Nombre, " ", "_")),
			Image:           &types.Image{Bytes: imgBytes},
		})

		if err != nil || len(indexRes.FaceRecords) == 0 {
			c.JSON(500, gin.H{"error": "Error al procesar rostro"})
			return
		}

		faceID := *indexRes.FaceRecords[0].Face.FaceId
		var nuevoPadreID int
		db.QueryRow("INSERT INTO padres (nombre, face_id, guarderia_id) VALUES ($1, $2, $3) RETURNING id",
			input.Nombre, faceID, gID).Scan(&nuevoPadreID)

		c.JSON(200, gin.H{"status": "OK", "padre_id": nuevoPadreID})
	})

	r.POST("/identificar", AuthMiddleware(), func(c *gin.Context) {
		gID, _ := c.Get("guarderia_id")

		colID := getCollectionID(gID) // <-- Buscamos SOLO en su colección

		var input struct {
			Imagen string `json:"imagen"`
		}
		c.BindJSON(&input)
		imgBytes, _ := base64.StdEncoding.DecodeString(input.Imagen)

		result, err := rekClient.SearchFacesByImage(context.TODO(), &rekognition.SearchFacesByImageInput{
			CollectionId:       aws.String(colID),
			FaceMatchThreshold: aws.Float32(90.0),
			Image:              &types.Image{Bytes: imgBytes},
			MaxFaces:           aws.Int32(1),
		})

		if err != nil || len(result.FaceMatches) == 0 {
			c.JSON(404, gin.H{"mensaje": "No reconocido en esta sede"})
			return
		}

		faceID := *result.FaceMatches[0].Face.FaceId
		confianza := float64(*result.FaceMatches[0].Similarity)

		// faceID y confianza quemados para tu prueba (o recuperados de Rekognition)
		//faceID := "9862103f-1b40-4c90-8dff-bb6e25b0700e"
		//confianza := 99.5

		// CONSULTA CORREGIDA: Filtramos la subconsulta por la fecha actual
		query := `
        SELECT 
            p.id, 
            p.nombre, 
            n.id, 
            n.nombre_niño,
            COALESCE((
                SELECT tipo_movimiento 
                FROM asistencia 
                WHERE hijo_id = n.id 
                  AND guarderia_id = $2 
                  AND fecha_hora::date = CURRENT_DATE 
                ORDER BY fecha_hora DESC 
                LIMIT 1
            ), 'AUSENTE') -- Si no hay registros HOY, el niño está AUSENTE
        FROM padres p
        LEFT JOIN tutor_hijos tn ON p.id = tn.padre_id
        LEFT JOIN hijos n ON tn.hijo_id = n.id AND n.activo = true
        WHERE p.face_id = $1 AND p.guarderia_id = $2`

		rows, err := db.Query(query, faceID, gID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error en consulta de base de datos"})
			return
		}
		defer rows.Close()

		var padreID int
		var nombrePadre string
		var hijos []Hijo

		// Mapa para evitar duplicados si un niño tiene varios tutores (opcional)
		for rows.Next() {
			var hID sql.NullInt64
			var hNom sql.NullString
			var hEst sql.NullString

			err := rows.Scan(&padreID, &nombrePadre, &hID, &hNom, &hEst)
			if err != nil {
				continue
			}

			if hID.Valid {
				hijos = append(hijos, Hijo{
					ID:           int(hID.Int64),
					Nombre:       hNom.String,
					UltimoEstado: hEst.String, // Aquí llegará 'AUSENTE', 'ENTRADA' o 'SALIDA' pero SOLO de hoy
				})
			}
		}

		c.JSON(200, RespuestaIdentificacion{
			PadreID: padreID, Padre: nombrePadre, Confianza: confianza, Hijos: hijos,
		})
	})

	r.POST("/registrar-hijo", AuthMiddleware(), func(c *gin.Context) {
		// 1. Extraemos el guarderia_id del token (inyectado por el Middleware)
		gID, exists := c.Get("guarderia_id")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo identificar la guardería"})
			return
		}

		var input struct {
			Nombre string `json:"nombre_niño"`
		}

		if err := c.BindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Nombre requerido"})
			return
		}

		var hijoID int
		// 2. Modificamos el INSERT para incluir el guarderia_id
		query := "INSERT INTO hijos (nombre_niño, guarderia_id) VALUES ($1, $2) RETURNING id"

		// 3. Ejecutamos la consulta pasando el nombre y el ID de la guardería
		err := db.QueryRow(query, input.Nombre, gID).Scan(&hijoID)
		if err != nil {
			fmt.Printf("Error al insertar hijo: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al crear niño en la base de datos"})
			return
		}

		// 4. Respuesta exitosa
		c.JSON(http.StatusOK, gin.H{
			"id":           hijoID,
			"nombre":       input.Nombre,
			"guarderia_id": gID,
		})
	})

	r.GET("/padre/:id/hijos", AuthMiddleware(), func(c *gin.Context) {
		// 1. Extraemos el guarderia_id del token
		gID, _ := c.Get("guarderia_id")

		// 2. Obtenemos el ID del padre de la URL
		padreID := c.Param("id")

		// 3. Consulta con DOBLE FILTRO:
		// Filtramos por padre_id Y por guarderia_id para asegurar que pertenezcan a la misma sede
		query := `
        SELECT h.id, h.nombre_niño, h.activo 
		FROM hijos h
		JOIN tutor_hijos th ON h.id = th.hijo_id 
		WHERE th.padre_id = $1 AND th.guarderia_id = $2`

		rows, err := db.Query(query, padreID, gID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al consultar hijos"})
			return
		}
		defer rows.Close()

		// Inicializamos como slice vacío para evitar que devuelva 'null' al frontend
		listaHijos := []Hijo{}

		for rows.Next() {
			var h Hijo
			// Solo escaneamos ID y Nombre según nuestro SELECT
			if err := rows.Scan(&h.ID, &h.Nombre, &h.Activo); err != nil {
				continue
			}
			listaHijos = append(listaHijos, h)
		}

		// 4. Respuesta
		// Si la lista está vacía, puede ser porque el padre no tiene hijos
		// o porque el padre pertenece a otra guardería.
		c.JSON(http.StatusOK, listaHijos)
	})

	r.POST("/confirmar-asistencia", AuthMiddleware(), func(c *gin.Context) {
		gID, _ := c.Get("guarderia_id")

		var req RegistroAsistencia
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
			return
		}

		// Buscamos el último registro de HOY
		var ultimoTipo string
		err := db.QueryRow(`
        SELECT tipo_movimiento 
        FROM asistencia 
        WHERE hijo_id = $1 
          AND guarderia_id = $2 
          AND fecha_hora::date = CURRENT_DATE 
        ORDER BY fecha_hora DESC 
        LIMIT 1`, req.HijoID, gID).Scan(&ultimoTipo)

		// Lógica de decisión:
		// 1. Si no hay registro hoy (err != nil) -> Es una ENTRADA.
		// 2. Si el último fue ENTRADA -> Es una SALIDA.
		// 3. Si el último fue SALIDA -> Podrías bloquearlo o permitir re-entrada (aquí lo seteamos como ENTRADA de nuevo).

		tipoFinal := "ENTRADA"
		if err == nil {
			if ultimoTipo == "ENTRADA" {
				tipoFinal = "SALIDA"
			} else if ultimoTipo == "SALIDA" {
				// Opcional: Bloquear si ya salió
				// c.JSON(400, gin.H{"error": "El niño ya marcó salida hoy"})
				// return
				tipoFinal = "ENTRADA" // Re-entrada
			}
		}

		query := `
        INSERT INTO asistencia (padre_id, hijo_id, aseado, reporte_golpe, observaciones, tipo_movimiento, guarderia_id) 
        VALUES ($1, $2, $3, $4, $5, $6, $7)`

		_, err = db.Exec(query, req.PadreID, req.HijoID, req.Aseado, req.ReporteGolpe, req.Observaciones, tipoFinal, gID)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo guardar"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  "Registro guardado",
			"tipo":    tipoFinal,
			"hijo_id": req.HijoID,
		})
	})

	r.POST("/vincular-tutor", AuthMiddleware(), func(c *gin.Context) {
		// 1. Obtener la guardería del token
		gID, _ := c.Get("guarderia_id")

		var req VinculacionRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
			return
		}

		// 2. Insertar en la tabla intermedia incluyendo el guarderia_id
		// El ON CONFLICT evita errores si intentan vincular al mismo padre/hijo dos veces
		query := `
        INSERT INTO tutor_hijos (padre_id, hijo_id, guarderia_id) 
        VALUES ($1, $2, $3) 
        ON CONFLICT (padre_id, hijo_id) DO NOTHING`

		_, err := db.Exec(query, req.PadreID, req.HijoID, gID)

		if err != nil {
			log.Printf("Error en vinculación: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo realizar la vinculación"})
			return
		}

		// 3. Respuesta exitosa
		c.JSON(http.StatusOK, gin.H{
			"status":   "Vinculación exitosa",
			"padre_id": req.PadreID,
			"hijo_id":  req.HijoID,
		})
	})

	r.GET("/buscar-hijos", AuthMiddleware(), func(c *gin.Context) {
		// 1. Obtener el ID de la guardería desde el token
		gID, _ := c.Get("guarderia_id")

		// 2. Obtener el parámetro de búsqueda
		queryParam := c.Query("q")

		// 3. Consulta SQL con DOBLE FILTRO
		// Filtramos por el nombre (ILIKE) Y obligatoriamente por guarderia_id
		query := `
        SELECT id, nombre_niño 
        FROM hijos 
        WHERE nombre_niño ILIKE $1 AND guarderia_id = $2
		AND activo = true 
        LIMIT 5`

		rows, err := db.Query(query, "%"+queryParam+"%", gID)

		// Inicializamos el slice vacío para que el frontend reciba [] y no null
		lista := []gin.H{}

		if err != nil {
			fmt.Printf("Error en buscar-hijos: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al consultar la base de datos"})
			return
		}
		defer rows.Close()

		// 4. Escanear resultados
		for rows.Next() {
			var id int
			var nombre string
			if err := rows.Scan(&id, &nombre); err != nil {
				continue
			}
			lista = append(lista, gin.H{
				"id":          id,
				"nombre_niño": nombre,
			})
		}

		// 5. Enviar respuesta (si no hay coincidencias, enviará [])
		c.JSON(http.StatusOK, lista)
	})

	r.GET("/buscar-padres", AuthMiddleware(), func(c *gin.Context) {
		// 1. Obtener la guardería del token
		gID, _ := c.Get("guarderia_id")

		queryParam := c.Query("q")

		// 2. Consulta con filtro de guarderia_id en la tabla de padres
		// Usamos p.guarderia_id = $2 para segmentar los datos
		var rows *sql.Rows
		var err error

		// Si queryParam está vacío, traemos todos los de la guardería
		if queryParam == "" {
			query := `
			SELECT p.id, p.nombre, COALESCE(h.id, 0), COALESCE(h.nombre_niño, '')
			FROM padres p
			LEFT JOIN tutor_hijos th ON p.id = th.padre_id
			LEFT JOIN hijos h ON th.hijo_id = h.id
			WHERE p.guarderia_id = $1
			ORDER BY p.nombre ASC`
			rows, err = db.Query(query, gID)
		} else {
			query := `
			SELECT p.id, p.nombre, COALESCE(h.id, 0), COALESCE(h.nombre_niño, '')
			FROM padres p
			LEFT JOIN tutor_hijos th ON p.id = th.padre_id
			LEFT JOIN hijos h ON th.hijo_id = h.id
			WHERE p.nombre ILIKE $1 AND p.guarderia_id = $2
			ORDER BY p.nombre ASC`
			rows, err = db.Query(query, "%"+queryParam+"%", gID)
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al consultar la base de datos"})
			return
		}
		defer rows.Close()

		// Estructura para agrupar hijos por padre (se mantiene igual)
		type PadreData struct {
			ID     int    `json:"id"`
			Nombre string `json:"nombre"`
			Hijos  []any  `json:"hijos"`
		}

		// Inicializamos el mapa y el slice de resultados
		padresMap := make(map[int]*PadreData)

		for rows.Next() {
			var pID int
			var pNombre string
			var hID int
			var hNombre string

			if err := rows.Scan(&pID, &pNombre, &hID, &hNombre); err != nil {
				continue
			}

			// Si el padre no está en el mapa, lo agregamos
			if _, ok := padresMap[pID]; !ok {
				padresMap[pID] = &PadreData{
					ID:     pID,
					Nombre: pNombre,
					Hijos:  []any{},
				}
			}

			// Si tiene un hijo vinculado, lo agregamos a su lista
			if hID != 0 {
				padresMap[pID].Hijos = append(padresMap[pID].Hijos, gin.H{
					"id":          hID,
					"nombre_niño": hNombre,
				})
			}
		}

		// Convertir mapa a slice para la respuesta JSON
		resultado := []PadreData{}
		for _, p := range padresMap {
			resultado = append(resultado, *p)
		}

		// Si no hay resultados, enviará [] en lugar de null
		c.JSON(http.StatusOK, resultado)
	})

	r.POST("/desvincular-hijo", AuthMiddleware(), func(c *gin.Context) {
		// 1. Obtener la guardería del token
		gID, _ := c.Get("guarderia_id")

		var input struct {
			PadreID int `json:"padre_id"`
			HijoID  int `json:"hijo_id"`
		}

		// Validamos el JSON recibido
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
			return
		}

		// 2. Ejecutar el DELETE con triple filtro
		// Aseguramos que solo se borre si la relación pertenece a esta guardería
		query := `
        DELETE FROM tutor_hijos 
        WHERE padre_id = $1 AND hijo_id = $2 AND guarderia_id = $3`

		result, err := db.Exec(query, input.PadreID, input.HijoID, gID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo realizar la desvinculación"})
			return
		}

		// 3. Verificar si realmente se borró algo
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"mensaje": "No se encontró la relación o no pertenece a esta guardería"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"mensaje": "Desvinculación exitosa"})
	})

	// En tu main.go o archivo de rutas
	r.POST("/actualizar-padre", AuthMiddleware(), func(c *gin.Context) {
		// 1. Obtener la guardería del token para validar propiedad
		gID, _ := c.Get("guarderia_id")

		var req struct {
			ID     int    `json:"id"`
			Nombre string `json:"nombre"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
			return
		}

		// 2. Ejecutar el UPDATE con doble filtro (ID + Guardería)
		// Esto garantiza que solo se actualice si el padre pertenece a la guardería del admin
		query := "UPDATE padres SET nombre = $1 WHERE id = $2 AND guarderia_id = $3"

		result, err := db.Exec(query, req.Nombre, req.ID, gID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error interno al actualizar"})
			return
		}

		// 3. Verificar si el registro existía para esa guardería
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Padre no encontrado o no pertenece a esta guardería"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "Nombre actualizado correctamente"})
	})

	r.GET("/bitacora", AuthMiddleware(), func(c *gin.Context) {
		// 1. Obtener el ID de la guardería desde el token
		gID, _ := c.Get("guarderia_id")

		fechaQuery := c.Query("fecha")
		if fechaQuery == "" {
			fechaQuery = time.Now().Format("2006-01-02")
		}

		// 2. Consulta SQL: Seleccionamos TODOS los niños (hijos)
		// y buscamos su ÚLTIMO movimiento de asistencia en la fecha elegida
		query := `
    SELECT 
        h.id, 
        h.nombre_niño,
        COALESCE(ult_mov.tipo_movimiento, 'AUSENTE') as estatus,
        COALESCE(ult_mov.fecha_hora::text, '') as fecha_hora,
        COALESCE(ult_mov.aseado, true) as aseado,
        COALESCE(ult_mov.reporte_golpe, false) as reporte_golpe,
        COALESCE(ult_mov.observaciones, '') as observaciones
    FROM hijos h
    LEFT JOIN LATERAL (
        /* Esta subconsulta busca el registro más reciente del niño para ese día */
        SELECT tipo_movimiento, fecha_hora, aseado, reporte_golpe, observaciones
        FROM asistencia
        WHERE hijo_id = h.id 
          AND guarderia_id = $1 
          AND fecha_hora::date = $2::date
        ORDER BY fecha_hora DESC
        LIMIT 1
    ) ult_mov ON true
    WHERE h.guarderia_id = $1 AND h.activo = true
    ORDER BY h.nombre_niño ASC`

		rows, err := db.Query(query, gID, fechaQuery)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al consultar estatus de alumnos"})
			return
		}
		defer rows.Close()

		registros := []map[string]interface{}{}

		for rows.Next() {
			var id int
			var niño, estatus, fecha, obs string
			var aseado, golpe bool

			err := rows.Scan(&id, &niño, &estatus, &fecha, &aseado, &golpe, &obs)
			if err != nil {
				continue
			}

			registros = append(registros, map[string]interface{}{
				"id":            id,
				"hijo":          niño,
				"estatus":       estatus, // ENTRADA, SALIDA o AUSENTE
				"fecha":         fecha,
				"aseado":        aseado,
				"golpe":         golpe,
				"observaciones": obs,
			})
		}

		c.JSON(http.StatusOK, registros)
	})

	// --- ENDPOINT REPORTES PERSONALIZADOS ---
	r.GET("/reportes-asistencia", AuthMiddleware(), func(c *gin.Context) {
		// 1. Obtener la guardería desde el token JWT
		gID, _ := c.Get("guarderia_id")

		inicio := c.Query("inicio")
		fin := c.Query("fin")

		// Si no se envían fechas, por defecto usamos el día de hoy
		if inicio == "" || fin == "" {
			hoy := time.Now().Format("2006-01-02")
			inicio = hoy
			fin = hoy
		}

		// 2. Consulta SQL con triple filtro: Rango de fechas Y Guardería
		query := `
        SELECT 
            a.fecha_hora, 
            h.nombre_niño, 
            p.nombre as tutor_nombre, 
            a.tipo_movimiento, 
            a.aseado, 
            a.reporte_golpe, 
            COALESCE(a.observaciones, '')
        FROM asistencia a
        JOIN hijos h ON a.hijo_id = h.id
        JOIN padres p ON a.padre_id = p.id
        WHERE a.fecha_hora::date >= $1 
          AND a.fecha_hora::date <= $2 
          AND a.guarderia_id = $3
        ORDER BY a.fecha_hora DESC`

		rows, err := db.Query(query, inicio, fin, gID)
		if err != nil {
			log.Printf("Error en reporte: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al consultar reportes"})
			return
		}
		defer rows.Close()

		reportes := []ReporteData{}
		for rows.Next() {
			var r ReporteData
			var fechaTime time.Time

			err := rows.Scan(
				&fechaTime,
				&r.HijoNombre,
				&r.TutorNombre,
				&r.Tipo,
				&r.Aseado,
				&r.ReporteGolpe,
				&r.Observaciones,
			)
			if err != nil {
				continue
			}

			// Formateamos la fecha para el frontend
			r.Fecha = fechaTime.Format("02/01/2006 15:04")
			reportes = append(reportes, r)
		}

		// Enviamos siempre un slice (aunque esté vacío) para evitar 'null' en el JSON
		c.JSON(http.StatusOK, reportes)
	})

	r.POST("/verificar-pin", AuthMiddleware(), func(c *gin.Context) {
		// 1. Obtener el ID del usuario desde el token
		userID, _ := c.Get("user_id")

		var req PinRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Formato de PIN inválido"})
			return
		}

		// 2. Consultar el PIN en la base de datos de autenticación
		var pinDB string
		err := dbAuth.QueryRow("SELECT pin_admin FROM usuarios WHERE id = $1", userID).Scan(&pinDB)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al verificar PIN"})
			return
		}

		// 3. Comparar (eliminando espacios en blanco por seguridad)
		if strings.TrimSpace(pinDB) != strings.TrimSpace(req.Pin) {
			c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": "PIN incorrecto"})
			return
		}

		// 4. Si es correcto
		c.JSON(http.StatusOK, gin.H{
			"valid":   true,
			"message": "PIN confirmado",
		})
	})

	r.PATCH("/hijos/:id/desactivar", AuthMiddleware(), func(c *gin.Context) {
		gID, _ := c.Get("guarderia_id")
		hijoID := c.Param("id")

		// En lugar de DELETE, hacemos UPDATE del campo 'activo'
		query := "UPDATE hijos SET activo = false WHERE id = $1 AND guarderia_id = $2"

		result, err := db.Exec(query, hijoID, gID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al dar de baja"})
			return
		}

		rows, _ := result.RowsAffected()
		if rows == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "Niño no encontrado"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"mensaje": "Alumno dado de baja correctamente"})
	})

	// --- EDITAR NOMBRE ---
	r.PUT("/hijos/:id", AuthMiddleware(), func(c *gin.Context) {
		gID, _ := c.Get("guarderia_id")
		hijoID := c.Param("id") // --- EDITAR NOMBRE ---

		var input struct {
			Nombre string `json:"nombre"`
		}
		if err := c.ShouldBindJSON(&input); err != nil || input.Nombre == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Nombre es requerido"})
			return
		}

		query := "UPDATE hijos SET nombre_niño = $1 WHERE id = $2 AND guarderia_id = $3"
		_, err := db.Exec(query, input.Nombre, hijoID, gID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al actualizar"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "Nombre actualizado"})
	})

	// --- REACTIVAR HIJO ---
	r.PATCH("/hijos/:id/activar", AuthMiddleware(), func(c *gin.Context) {
		gID, _ := c.Get("guarderia_id")
		hijoID := c.Param("id")

		query := "UPDATE hijos SET activo = true WHERE id = $1 AND guarderia_id = $2"

		_, err := db.Exec(query, hijoID, gID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al reactivar"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"mensaje": "Alumno reactivado correctamente"})
	})

	r.Run(":8099")
}

func RunMigrations() {
	fmt.Println("Ejecutando migraciones...")

	// El orden es importante por las llaves foráneas (Foreign Keys)
	queries := []string{
		// 1. Tabla Guarderías
		`CREATE TABLE IF NOT EXISTS guarderias (
			id SERIAL PRIMARY KEY,
			nombre VARCHAR(100) NOT NULL,
			slug VARCHAR(50) UNIQUE NOT NULL,
			direccion TEXT,
			plan_suscripcion VARCHAR(20) DEFAULT 'basico',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		// 2. Tabla Usuarios
		`CREATE TABLE IF NOT EXISTS usuarios (
			id SERIAL PRIMARY KEY,
			guarderia_id INTEGER REFERENCES guarderias(id) ON DELETE CASCADE,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			pin_admin VARCHAR(4) NOT NULL,
			rol VARCHAR(20) DEFAULT 'staff' CHECK (rol IN ('admin', 'staff')),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		// 3. Tabla Hijos
		`CREATE TABLE IF NOT EXISTS hijos (
			id SERIAL PRIMARY KEY,
			nombre_niño VARCHAR(100) NOT NULL,
			guarderia_id INTEGER REFERENCES guarderias(id) ON DELETE CASCADE
		);`,

		// 4. Tabla Padres
		`CREATE TABLE IF NOT EXISTS padres (
			id SERIAL PRIMARY KEY,
			nombre VARCHAR(100) NOT NULL,
			face_id VARCHAR(255) UNIQUE NOT NULL,
			guarderia_id INTEGER REFERENCES guarderias(id) ON DELETE CASCADE,
			creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		// 5. Tabla Intermedia Tutor_Hijos
		`CREATE TABLE IF NOT EXISTS tutor_hijos (
			padre_id INTEGER REFERENCES padres(id) ON DELETE CASCADE,
			hijo_id INTEGER REFERENCES hijos(id) ON DELETE CASCADE,
			guarderia_id INTEGER REFERENCES guarderias(id) ON DELETE CASCADE,
			PRIMARY KEY (padre_id, hijo_id)
		);`,

		// 6. Tabla Asistencia
		`CREATE TABLE IF NOT EXISTS asistencia (
			id SERIAL PRIMARY KEY,
			padre_id INTEGER REFERENCES padres(id) ON DELETE CASCADE,
			hijo_id INTEGER REFERENCES hijos(id) ON DELETE CASCADE,
			guarderia_id INTEGER REFERENCES guarderias(id) ON DELETE CASCADE,
			fecha_hora TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			aseado BOOLEAN DEFAULT true,
			reporte_golpe BOOLEAN DEFAULT false,
			observaciones TEXT,
			tipo_movimiento VARCHAR(20) CHECK (tipo_movimiento IN ('ENTRADA', 'SALIDA', 'REGISTRO'))
		);`,

		// 7. Índices adicionales
		`CREATE INDEX IF NOT EXISTS idx_asistencia_fecha ON asistencia (fecha_hora DESC);`,
	}

	for _, q := range queries {
		// Ejecutamos en dbAuth o db según donde quieras que vivan.
		// Si usas una sola BD, usa db. Si usas la de Auth para usuarios, separa la lógica.
		_, err := db.Exec(q)
		if err != nil {
			log.Printf("Error ejecutando migración: %v", err)
		}
	}

	// Si tienes dos bases de datos separadas (DATABASE_URL y DATABASE_URL_AUTH)
	// asegúrate de ejecutar las tablas correspondientes en la conexión correcta.
	fmt.Println("Migraciones finalizadas exitosamente.")
}
