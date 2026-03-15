package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rekognition"
	"github.com/aws/aws-sdk-go-v2/service/rekognition/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types" // <--- AGREGA ESTO CON ESTE ALIAS
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"
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

type SeguimientoDiario struct {
	HijoID        int    `json:"hijo_id"`
	GuarderiaID   int    `json:"guarderia_id"`
	Fecha         string `json:"fecha"` // YYYY-MM-DD
	Desayuno      string `json:"desayuno"`
	Comida        string `json:"comida"`
	Merienda      string `json:"merienda"`
	Esfinter      string `json:"esfinter"`
	Observaciones string `json:"observaciones"`
	FotoURL       string `json:"foto_url"`
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

	iniciarTareasProgramadas(db)

	r.POST("/usuarios/registro", func(c *gin.Context) {
		// 1. Estructura para recibir los datos (ajustada a tu tabla)
		var nuevoUsuario struct {
			Username    string `json:"username"`
			Password    string `json:"password"`
			GuarderiaID int    `json:"guarderia_id"`
			Rol         string `json:"rol"`
			PinAdmin    string `json:"pin_admin"`
		}

		// Validar JSON
		if err := c.ShouldBindJSON(&nuevoUsuario); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
			return
		}

		// 2. ENCRIPTACIÓN: Generar el Hash de la contraseña
		// El costo 10 es el estándar recomendado para el plan Professional que manejas
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(nuevoUsuario.Password), 10)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al procesar seguridad"})
			return
		}

		// 3. Inserción en la Base de Datos
		query := `
        INSERT INTO usuarios (username, password_hash, guarderia_id, rol, pin_admin)
        VALUES ($1, $2, $3, $4, $5)`

		_, err = dbAuth.Exec(query,
			nuevoUsuario.Username,
			string(hashedPassword), // Guardamos el hash, NO la contraseña plana
			nuevoUsuario.GuarderiaID,
			nuevoUsuario.Rol,
			nuevoUsuario.PinAdmin,
		)

		if err != nil {
			fmt.Printf("Error al insertar usuario: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo crear el usuario"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "Usuario creado exitosamente con hash de seguridad"})
	})

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
		var passHash, rol, pin, gNombre, gSlug string
		// 2. Consulta a la base de datos
		query := `
		SELECT 
            u.id, u.guarderia_id, u.password_hash, u.rol, u.pin_admin,
            g.nombre, g.slug
        FROM usuarios u
        INNER JOIN guarderias g ON u.guarderia_id = g.id
        WHERE u.username = $1`

		err := dbAuth.QueryRow(query, creds.Username).Scan(&id, &gID, &passHash, &rol, &pin, &gNombre, &gSlug)
		if err != nil {
			if err == sql.ErrNoRows {
				fmt.Printf("Usuario no encontrado: %s\n", creds.Username)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Usuario no existe"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error de BD"})
			}
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(passHash), []byte(creds.Password))
		if err != nil {
			// Si el error no es nulo, la contraseña no coincide
			fmt.Printf("FALLO: Intento de login inválido para usuario %s\n", creds.Username)
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
			"token":            tokenStr,
			"guarderia_id":     gID,
			"guarderia_nombre": gNombre, // Nuevo
			"guarderia_slug":   gSlug,   // Nuevo
			"rol":              rol,
			"username":         creds.Username,
			"pin_admin":        pin,
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
		colID := getCollectionID(gID)

		var input struct {
			Imagen string `json:"imagen"`
		}
		if err := c.BindJSON(&input); err != nil {
			c.JSON(400, gin.H{"error": "Imagen requerida"})
			return
		}

		imgBytes, _ := base64.StdEncoding.DecodeString(input.Imagen)

		// 1. Identificación facial con Rekognition
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

		// 2. CONSULTA CON ZONA HORARIA CORRECTA (America/Mazatlan para Culiacán)
		// Esta query asegura que "hoy" termine a las 12:00 AM de Culiacán, no de Londres.
		query := `
		SELECT 
	        p.id AS padre_id, 
			p.nombre AS padre_nombre, 
			n.id AS hijo_id, 
			n.nombre_niño AS hijo_nombre, 
			COALESCE((
				SELECT tipo_movimiento 
				FROM asistencia 
				WHERE hijo_id = n.id 
				AND guarderia_id = $2 
				-- Solo un AT TIME ZONE para convertir de UTC a local correctamente
				AND (fecha_hora AT TIME ZONE 'America/Mazatlan')::date = 
					(CURRENT_TIMESTAMP AT TIME ZONE 'America/Mazatlan')::date
				ORDER BY fecha_hora DESC 
				LIMIT 1
			), 'AUSENTE') as ultimo_estado
		FROM padres p
		INNER JOIN tutor_hijos tn ON p.id = tn.padre_id
		INNER JOIN hijos n ON tn.hijo_id = n.id
		WHERE p.face_id = $1 
		AND p.guarderia_id = $2 
		AND n.activo = true`

		rows, err := db.Query(query, faceID, gID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error en base de datos: " + err.Error()})
			return
		}
		defer rows.Close()

		var padreID int
		var nombrePadre string
		var hijos []Hijo // Asegúrate de tener definido type Hijo struct { ID int; Nombre string; UltimoEstado string }

		for rows.Next() {
			var hID int
			var hNom string
			var hEst string

			// Escaneamos directamente ya que el INNER JOIN garantiza que existan
			err := rows.Scan(&padreID, &nombrePadre, &hID, &hNom, &hEst)
			if err != nil {
				continue
			}

			hijos = append(hijos, Hijo{
				ID:           hID,
				Nombre:       hNom,
				UltimoEstado: hEst,
			})
		}

		// 3. Respuesta al Frontend
		if len(hijos) == 0 {
			c.JSON(404, gin.H{"mensaje": "Padre identificado pero no tiene hijos activos asignados"})
			return
		}

		c.JSON(200, RespuestaIdentificacion{
			PadreID:   padreID,
			Padre:     nombrePadre,
			Confianza: confianza,
			Hijos:     hijos,
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
		tokenUsuarioID, _ := c.Get("user_id") // ID del usuario logueado
		rol, _ := c.Get("rol")                // Rol del usuario

		// 2. Obtenemos el ID del padre de la URL
		padreID := c.Param("id")

		// --- LÓGICA DE COMODÍN PARA EL PAPÁ ---
		// Si el ID es "0", usamos el ID que viene dentro del Token
		if padreID == "0" {
			// Convertimos el ID del token a string para la consulta si es necesario
			padreID = fmt.Sprintf("%v", tokenUsuarioID)
		} else {
			// SEGURIDAD: Si no es "0", verificamos que quien consulta sea ADMIN o STAFF
			// Esto evita que un papá cambie el "0" por el ID de otro papá en la URL
			if rol != "admin" && rol != "staff" {
				c.JSON(http.StatusForbidden, gin.H{"error": "No tienes permiso para consultar otros IDs"})
				return
			}
		}
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
		gID, _ := c.Get("guarderia_id")
		fechaQuery := c.Query("fecha")

		if fechaQuery == "" {
			loc, _ := time.LoadLocation("America/Mazatlan")
			fechaQuery = time.Now().In(loc).Format("2006-01-02")
		}

		// Definimos el rango del día en formato ISO para Postgres
		// Esto cubrirá todo el día sin importar el desfase de horas UTC
		inicioDia := fechaQuery + " 00:00:00-07" // -07 es el offset de Mazatlán
		finDia := fechaQuery + " 23:59:59-07"

		query := `
			SELECT 
				h.id, 
				h.nombre_niño,
				COALESCE(ult_mov.tipo_movimiento, 'AUSENTE') as estatus,
				COALESCE(TO_CHAR(ult_mov.fecha_hora AT TIME ZONE 'America/Mazatlan', 'HH12:MI AM'), '--:--') as hora_formateada,
				COALESCE(ult_mov.aseado, true) as aseado,
				COALESCE(ult_mov.reporte_golpe, false) as reporte_golpe,
				COALESCE(ult_mov.observaciones, '') as observaciones
			FROM hijos h
			LEFT JOIN LATERAL (
				SELECT tipo_movimiento, fecha_hora, aseado, reporte_golpe, observaciones
				FROM asistencia
				WHERE hijo_id = h.id 
				AND (fecha_hora >= $2::timestamptz AND fecha_hora <= $3::timestamptz)
				ORDER BY fecha_hora DESC
				LIMIT 1
			) ult_mov ON true
			WHERE h.guarderia_id = $1 AND h.activo = true
			ORDER BY h.nombre_niño ASC`

		rows, err := db.Query(query, gID, inicioDia, finDia)
		if err != nil {
			log.Printf("Error SQL Bitacora: %v", err)
			c.JSON(500, gin.H{"error": "Error de base de datos"})
			return
		}
		defer rows.Close()

		var registros []map[string]interface{}
		for rows.Next() {
			var id int
			var niño, estatus, hora, obs string
			var aseado, golpe bool
			if err := rows.Scan(&id, &niño, &estatus, &hora, &aseado, &golpe, &obs); err != nil {
				continue
			}
			registros = append(registros, map[string]interface{}{
				"id": id, "hijo": niño, "estatus": estatus, "fecha_hora": hora,
				"aseado": aseado, "golpe": golpe, "observaciones": obs,
			})
		}

		if registros == nil {
			registros = []map[string]interface{}{}
		}
		c.JSON(200, registros)
	})

	// --- ENDPOINT REPORTES PERSONALIZADOS ---
	r.GET("/reportes-asistencia", AuthMiddleware(), func(c *gin.Context) {
		gID, _ := c.Get("guarderia_id")
		inicio := c.Query("inicio")
		fin := c.Query("fin")

		if inicio == "" || fin == "" {
			loc, _ := time.LoadLocation("America/Mazatlan")
			hoy := time.Now().In(loc).Format("2006-01-02")
			inicio = hoy
			fin = hoy
		}

		// El cambio principal es el LEFT JOIN con seguimiento basado en la fecha del registro
		query := `
        SELECT 
            TO_CHAR(a.fecha_hora AT TIME ZONE 'America/Mazatlan', 'YYYY-MM-DD HH24:MI:SS') as fecha_formateada,
            h.nombre_niño, 
            p.nombre as tutor_nombre, 
            a.tipo_movimiento, 
            a.aseado, 
            a.reporte_golpe, 
            COALESCE(a.observaciones, '') as obs_asistencia,
            -- Nuevos campos pedagógicos de la bitácora
            COALESCE(s.desayuno, '') as desayuno,
            COALESCE(s.comida, '') as comida,
            COALESCE(s.merienda, '') as merienda,
            COALESCE(s.esfinter, '') as esfinter,
            COALESCE(s.durmio, false) as durmio,
            COALESCE(s.observaciones, '') as obs_pedagogicas
        FROM asistencia a
        INNER JOIN hijos h ON a.hijo_id = h.id
        INNER JOIN padres p ON a.padre_id = p.id
        -- Unimos con seguimiento usando el ID del hijo y la FECHA (sin hora) del movimiento
        LEFT JOIN seguimiento_diario s ON s.hijo_id = a.hijo_id 
            AND s.fecha = (a.fecha_hora AT TIME ZONE 'America/Mazatlan')::date
        WHERE a.guarderia_id = $3
          AND (a.fecha_hora AT TIME ZONE 'America/Mazatlan')::date >= $1::date
          AND (a.fecha_hora AT TIME ZONE 'America/Mazatlan')::date <= $2::date
        ORDER BY a.fecha_hora DESC`

		rows, err := db.Query(query, inicio, fin, gID)
		if err != nil {
			log.Printf("Error en reporte detallado: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al consultar reportes"})
			return
		}
		defer rows.Close()

		var reportes []map[string]interface{}
		for rows.Next() {
			var fecha, niño, tutor, tipo, obsAsis, desayuno, comida, merienda, esfinter, obsPed string
			var aseado, golpe, durmio bool

			err := rows.Scan(
				&fecha, &niño, &tutor, &tipo, &aseado, &golpe, &obsAsis,
				&desayuno, &comida, &merienda, &esfinter, &durmio, &obsPed,
			)
			if err != nil {
				log.Printf("Error escaneando fila: %v", err)
				continue
			}

			// Estructuramos la respuesta para que el Frontend la maneje fácilmente
			reportes = append(reportes, map[string]interface{}{
				"fecha":          fecha, //
				"hijo_nombre":    niño,  //
				"tutor_nombre":   tutor, //
				"tipo":           tipo,  //
				"aseado":         aseado,
				"golpe":          golpe,
				"obs_asistencia": obsAsis,
				"bitacora": map[string]interface{}{
					"desayuno":      desayuno, //
					"comida":        comida,   //
					"merienda":      merienda, //
					"esfinter":      esfinter, //
					"durmio":        durmio,   //
					"observaciones": obsPed,   //
				},
			})
		}

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

	// Endpoint para que el admin fuerce la entrada o salida
	r.POST("/admin/forzar-estatus", AuthMiddleware(), func(c *gin.Context) {
		var req struct {
			HijoID     int    `json:"hijo_id"`
			Movimiento string `json:"tipo_movimiento"` // "ENTRADA" o "SALIDA"
		}

		// 1. Obtener datos del Token y Body
		// Extraemos guarderia_id y userID del contexto (inyectados por tu Middleware de Auth)
		gID, _ := c.Get("guarderia_id")

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
			return
		}

		// 2. Manejo de Zona Horaria (Igual que en tu Cron)
		location, err := time.LoadLocation("America/Mazatlan")
		if err != nil {
			location = time.UTC // Fallback por seguridad
		}
		ahora := time.Now().In(location)

		// 3. Buscar el padre_id del ÚLTIMO registro de asistencia de ese niño
		var padreID int
		err = db.QueryRow(`
        SELECT padre_id 
        FROM asistencia 
        WHERE hijo_id = $1 
        ORDER BY fecha_hora DESC 
        LIMIT 1`, req.HijoID).Scan(&padreID)

		if err != nil {
			if err == sql.ErrNoRows {
				// FALLBACK: Si no hay historial, buscamos al tutor asignado en tutor_hijos
				err = db.QueryRow("SELECT padre_id FROM tutor_hijos WHERE hijo_id = $1 LIMIT 1", req.HijoID).Scan(&padreID)
				if err != nil {
					c.JSON(http.StatusNotFound, gin.H{"error": "El niño no tiene historial ni tutor asignado"})
					return
				}
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al consultar historial"})
				return
			}
		}

		// 4. Insertar en 'asistencia' usando la hora localizada
		// Cambiamos CURRENT_TIMESTAMP por $5 para pasarle la variable 'ahora'
		query := `
        INSERT INTO asistencia (hijo_id, padre_id, guarderia_id, tipo_movimiento, fecha_hora, observaciones) 
        VALUES ($1, $2, $3, $4, $5, $6)`

		observacion := fmt.Sprintf("Actualizado por Admin")

		_, err = db.Exec(query, req.HijoID, padreID, gID, req.Movimiento, ahora, observacion)
		if err != nil {
			fmt.Println("Error al forzar estatus:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo registrar el movimiento"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Estatus actualizado correctamente",
			"detalles": gin.H{
				"movimiento": req.Movimiento,
				"hora_local": ahora.Format("15:04:05"),
			},
		})
	})

	// --- ACTUALIZAR O CREAR BITÁCORA DIARIA (Punto 1) ---
	r.POST("/seguimiento", AuthMiddleware(), func(c *gin.Context) {
		gID, _ := c.Get("guarderia_id")

		// 1. Obtener datos de texto del Formulario
		hijoID := c.PostForm("hijo_id")
		desayuno := c.PostForm("desayuno")
		comida := c.PostForm("comida")
		merienda := c.PostForm("merienda")
		esfinter := c.PostForm("esfinter")
		observaciones := c.PostForm("observaciones")

		durmio := c.PostForm("durmio") == "true"

		// 2. Manejo de Fecha Local
		location, err := time.LoadLocation("America/Mazatlan")
		if err != nil {
			location = time.UTC
		}
		ahora := time.Now().In(location)
		fechaHoy := ahora.Format("2006-01-02")

		// 3. Query UPSERT: Insertamos o actualizamos y RETORNAMOS el ID del registro
		// Nota: Eliminamos foto_url de aquí porque ahora van a otra tabla
		var seguimientoID int
		query := `
        INSERT INTO seguimiento_diario 
        (hijo_id, guarderia_id, fecha, desayuno, comida, merienda, esfinter, observaciones, durmio)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (hijo_id, fecha) 
        DO UPDATE SET 
            desayuno = EXCLUDED.desayuno,
            comida = EXCLUDED.comida,
            merienda = EXCLUDED.merienda,
            esfinter = EXCLUDED.esfinter,
            observaciones = EXCLUDED.observaciones,
            durmio = EXCLUDED.durmio	
        RETURNING id;`

		err = db.QueryRow(query, hijoID, gID, fechaHoy, desayuno, comida, merienda, esfinter, observaciones, durmio).Scan(&seguimientoID)
		if err != nil {
			fmt.Println("Error al guardar bitácora:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo actualizar la bitácora"})
			return
		}

		// 4. Manejo de MÚLTIPLES FOTOS
		// Recogemos todos los archivos que vengan bajo la llave "fotos"
		form, _ := c.MultipartForm()
		files := form.File["fotos"]

		var urlsSubidas []string

		for _, file := range files {
			// Generamos un nombre único para cada foto dentro de su carpeta
			nombreArchivo := fmt.Sprintf("guarderia_%v/hijo_%s/%s_%s_%s",
				gID, hijoID, fechaHoy, ahora.Format("150405"), file.Filename)

			// Subimos a S3 usando tu función existente
			url, errS3 := uploadToS3(file, nombreArchivo)
			if errS3 != nil {
				fmt.Printf("Error subiendo archivo %s a S3: %v\n", file.Filename, errS3)
				continue // Si falla una foto, intentamos con la siguiente
			}

			// 5. Insertamos la URL en la tabla de fotos vinculada al seguimientoID
			_, errDBFoto := db.Exec("INSERT INTO fotos_seguimiento (seguimiento_id, url) VALUES ($1, $2)", seguimientoID, url)
			if errDBFoto != nil {
				fmt.Println("Error guardando URL en DB:", errDBFoto)
			} else {
				urlsSubidas = append(urlsSubidas, url)
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"mensaje":        "Información de bitácora y fotos guardadas correctamente",
			"seguimiento_id": seguimientoID,
			"fotos_subidas":  len(urlsSubidas),
			"urls":           urlsSubidas,
		})
	})

	r.GET("/seguimiento/:hijo_id", AuthMiddleware(), func(c *gin.Context) {
		hijoID := c.Param("hijo_id")

		// 1. Obtener la fecha de la URL (ej: ?fecha=2024-03-05)
		// Si no viene en la URL, usamos la fecha de hoy
		fechaConsulta := c.Query("fecha")

		location, _ := time.LoadLocation("America/Mazatlan")
		if fechaConsulta == "" {
			fechaConsulta = time.Now().In(location).Format("2006-01-02")
		}

		// Estructura para la respuesta
		type SeguimientoCompleto struct {
			ID            int      `json:"id"`
			HijoID        int      `json:"hijo_id"`
			Fecha         string   `json:"fecha"`
			Desayuno      string   `json:"desayuno"`
			Comida        string   `json:"comida"`
			Merienda      string   `json:"merienda"`
			Esfinter      string   `json:"esfinter"`
			Observaciones string   `json:"observaciones"`
			Durmio        bool     `json:"durmio"`
			Fotos         []string `json:"fotos"`
		}

		var s SeguimientoCompleto

		// 2. Consulta principal (Datos de la bitácora)
		querySeguimiento := `
        SELECT id, hijo_id, fecha, desayuno, comida, merienda, esfinter, observaciones, durmio 
        FROM seguimiento_diario 
        WHERE hijo_id = $1 AND fecha = $2`

		err := db.QueryRow(querySeguimiento, hijoID, fechaConsulta).Scan(
			&s.ID, &s.HijoID, &s.Fecha, &s.Desayuno, &s.Comida,
			&s.Merienda, &s.Esfinter, &s.Observaciones, &s.Durmio,
		)

		if err != nil {
			// Si no hay datos, enviamos un 404 con un mensaje amigable
			c.JSON(http.StatusNotFound, gin.H{
				"error": "No hay reporte disponible para la fecha: " + fechaConsulta,
			})
			return
		}

		// 3. Consulta de fotos (Todas las que pertenezcan a ese ID de seguimiento)
		rows, err := db.Query("SELECT url FROM fotos_seguimiento WHERE seguimiento_id = $1", s.ID)
		if err == nil {
			defer rows.Close()
			s.Fotos = []string{} // Inicializamos como array vacío para que no sea 'null' en JSON
			for rows.Next() {
				var url string
				if err := rows.Scan(&url); err == nil {
					s.Fotos = append(s.Fotos, url)
				}
			}
		}

		c.JSON(http.StatusOK, s)
	})

	r.Run(":8099")
}

func uploadToS3(fileHeader *multipart.FileHeader, fileName string) (string, error) {
	// Abrir el archivo que viene del formulario
	file, err := fileHeader.Open()
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Leer el contenido a un buffer de bytes
	buffer, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	// Cargar configuración de AWS (tomará las variables de entorno de Render/Sistema)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return "", err
	}

	client := s3.NewFromConfig(cfg)
	bucketName := "biosafe-storage-fotos" // Tu bucket recién creado

	// Subir el objeto a S3
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(bucketName),
		Key:         aws.String(fileName),
		Body:        bytes.NewReader(buffer),
		ContentType: aws.String("image/jpeg"),          // Ajusta si permites otros formatos
		ACL:         s3types.ObjectCannedACLPublicRead, // Esto permite que el papá vea la foto
	})

	if err != nil {
		return "", err
	}

	// Construir la URL pública de la imagen
	// La URL sigue el patrón: https://bucket.s3.region.amazonaws.com/key
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	} // Fallback si no está la variable

	url := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucketName, region, fileName)
	return url, nil
}

func iniciarTareasProgramadas(db *sql.DB) {
	location, err := time.LoadLocation("America/Mazatlan")
	if err != nil {
		log.Printf("Error cargando zona horaria: %v", err)
		location = time.UTC
	}

	c := cron.New(cron.WithLocation(location))

	// Prueba ajustando a unos minutos adelante de tu hora actual
	_, err = c.AddFunc("0 23 * * *", func() {
		ahora := time.Now().In(location)
		// Definimos el inicio y fin del día actual para la consulta
		inicioDia := time.Date(ahora.Year(), ahora.Month(), ahora.Day(), 0, 0, 0, 0, location)
		finDia := inicioDia.Add(24 * time.Hour)

		log.Printf("Iniciando cierre automático [%s] entre %v y %v",
			ahora.Format("15:04:05"), inicioDia.Format("2006-01-02"), finDia.Format("2006-01-02"))

		query := `
            INSERT INTO asistencia (hijo_id, padre_id, guarderia_id, tipo_movimiento, fecha_hora, observaciones)
            SELECT DISTINCT ON (a1.hijo_id) 
                a1.hijo_id, 
                a1.padre_id, 
                a1.guarderia_id, 
                'SALIDA', 
                $1::timestamp with time zone, 
                'Cierre automático nocturno'
            FROM asistencia a1
            WHERE a1.tipo_movimiento = 'ENTRADA'
            AND a1.fecha_hora >= $2 AND a1.fecha_hora < $3
            AND NOT EXISTS (
                SELECT 1 FROM asistencia a2 
                WHERE a2.hijo_id = a1.hijo_id 
                AND a2.tipo_movimiento = 'SALIDA' 
                AND a2.fecha_hora >= $2 AND a2.fecha_hora < $3
            )
            ORDER BY a1.hijo_id, a1.fecha_hora DESC`

		// Pasamos: 1. El momento de la salida, 2. Inicio del día, 3. Fin del día
		result, err := db.Exec(query, ahora, inicioDia, finDia)
		if err != nil {
			log.Printf("FALLO en el cierre: %v", err)
			return
		}

		filas, _ := result.RowsAffected()
		log.Printf("Cierre completado. Niños actualizados: %d", filas)
	})

	c.Start()
	log.Println("Cron iniciado con rango de fechas seguro")
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

		// Nueva tabla para el seguimiento diario
		`CREATE TABLE IF NOT EXISTS seguimiento_diario (
			id SERIAL PRIMARY KEY,
			hijo_id INTEGER REFERENCES hijos(id) ON DELETE CASCADE,
			guarderia_id INTEGER REFERENCES guarderias(id) ON DELETE CASCADE,
			fecha DATE DEFAULT CURRENT_DATE,
			desayuno VARCHAR(20) DEFAULT 'pendiente', -- 'no_comio', 'poco', 'todo'
			comida VARCHAR(20) DEFAULT 'pendiente',
			merienda VARCHAR(20) DEFAULT 'pendiente',
			esfinter VARCHAR(50), 
			foto_url TEXT,
			observaciones TEXT,
			UNIQUE(hijo_id, fecha) -- Evita duplicados para el mismo niño el mismo día
		);`,

		`CREATE TABLE fotos_seguimiento (
			id SERIAL PRIMARY KEY,
			seguimiento_id INT REFERENCES seguimiento_diario(id),
			url TEXT NOT NULL,
			creado_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
