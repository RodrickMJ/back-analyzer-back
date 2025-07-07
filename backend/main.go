package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type Token struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type Error struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Severity   string `json:"severity"`
	Suggestion string `json:"suggestion,omitempty"`
}

type VirtualHost struct {
	Address      string            `json:"address"`
	Port         string            `json:"port"`
	ServerName   string            `json:"serverName"`
	DocumentRoot string            `json:"documentRoot"`
	ErrorLog     string            `json:"errorLog"`
	AccessLog    string            `json:"accessLog"`
	Directives   map[string]string `json:"directives"`
	Line         int               `json:"line"`
}

type AnalysisResult struct {
	Tokens       []Token       `json:"tokens"`
	Errors       []Error       `json:"errors"`
	VirtualHosts []VirtualHost `json:"virtualHosts"`
	Summary      Summary       `json:"summary"`
}

type Summary struct {
	TotalLines      int `json:"totalLines"`
	LexicalErrors   int `json:"lexicalErrors"`
	SyntacticErrors int `json:"syntacticErrors"`
	SemanticErrors  int `json:"semanticErrors"`
	VirtualHosts    int `json:"virtualHosts"`
}

type AnalysisRequest struct {
	Content        string `json:"content"`
	ValidateFiles  bool   `json:"validateFiles"` // Nueva opción
	ServerBasePath string `json:"serverBasePath,omitempty"` // Ruta base del servidor
}

// Analizador léxico
type Lexer struct {
	input    string
	position int
	line     int
	column   int
	tokens   []Token
	errors   []Error
}

func NewLexer(input string) *Lexer {
	return &Lexer{
		input:  input,
		line:   1,
		column: 1,
		tokens: []Token{},
		errors: []Error{},
	}
}

func (l *Lexer) addToken(tokenType, value string) {
	l.tokens = append(l.tokens, Token{
		Type:   tokenType,
		Value:  value,
		Line:   l.line,
		Column: l.column - len(value),
	})
}

func (l *Lexer) addError(message string) {
	l.errors = append(l.errors, Error{
		Type:     "lexical",
		Message:  message,
		Line:     l.line,
		Column:   l.column,
		Severity: "error",
	})
}

func (l *Lexer) peek() byte {
	if l.position >= len(l.input) {
		return 0
	}
	return l.input[l.position]
}

func (l *Lexer) advance() byte {
	if l.position >= len(l.input) {
		return 0
	}
	ch := l.input[l.position]
	l.position++
	if ch == '\n' {
		l.line++
		l.column = 1
	} else {
		l.column++
	}
	return ch
}

func (l *Lexer) skipWhitespace() {
	for l.peek() == ' ' || l.peek() == '\t' || l.peek() == '\r' {
		l.advance()
	}
}

func (l *Lexer) readWord() string {
	var result strings.Builder
	for l.peek() != 0 && (isLetter(l.peek()) || isDigit(l.peek()) || l.peek() == '_' || l.peek() == '-' || l.peek() == '.') {
		result.WriteByte(l.advance())
	}
	return result.String()
}

func (l *Lexer) readPath() string {
	var result strings.Builder
	for l.peek() != 0 && l.peek() != ' ' && l.peek() != '\t' && l.peek() != '\n' && l.peek() != '#' {
		result.WriteByte(l.advance())
	}
	return result.String()
}

func (l *Lexer) readRestOfLine() string {
	var result strings.Builder
	l.skipWhitespace()
	
	for l.peek() != 0 && l.peek() != '\n' && l.peek() != '#' {
		result.WriteByte(l.advance())
	}
	
	return strings.TrimSpace(result.String())
}

func (l *Lexer) readQuotedString() string {
	var result strings.Builder
	quote := l.advance()

	for l.peek() != 0 && l.peek() != quote {
		if l.peek() == '\\' {
			l.advance()
			if l.peek() != 0 {
				result.WriteByte(l.advance())
			}
		} else {
			result.WriteByte(l.advance())
		}
	}

	if l.peek() == quote {
		l.advance()
	} else {
		l.addError("Unterminated quoted string")
	}

	return result.String()
}

func (l *Lexer) readComment() string {
	var result strings.Builder
	for l.peek() != 0 && l.peek() != '\n' {
		result.WriteByte(l.advance())
	}
	return result.String()
}

func (l *Lexer) Tokenize() ([]Token, []Error) {
	for l.position < len(l.input) {
		l.skipWhitespace()

		if l.peek() == 0 {
			break
		}

		ch := l.peek()

		switch ch {
		case '\n':
			l.advance()
			continue
		case '#':
			comment := l.readComment()
			l.addToken("COMMENT", comment)
		case '<':
			l.advance()
			if l.peek() == '/' {
				l.advance()
				tag := l.readWord()
				if l.peek() == '>' {
					l.advance()
					l.addToken("CLOSE_TAG", tag)
				} else {
					l.addError("Expected '>' after closing tag")
				}
			} else {
				tag := l.readWord()
				l.skipWhitespace()
				
				var params strings.Builder
				for l.peek() != 0 && l.peek() != '>' {
					if l.peek() == '\n' {
						l.addError("Unterminated tag")
						break
					}
					params.WriteByte(l.advance())
				}

				if l.peek() == '>' {
					l.advance()
					l.addToken("OPEN_TAG", tag)
					if params.Len() > 0 {
						l.addToken("TAG_PARAMS", strings.TrimSpace(params.String()))
					}
				} else {
					l.addError("Expected '>' after opening tag")
				}
			}
		case '"', '\'':
			quoted := l.readQuotedString()
			l.addToken("QUOTED_STRING", quoted)
		default:
			if isLetter(ch) || ch == '_' {
				word := l.readWord()
				// Verificar si es una directiva conocida
				if isValidDirective(word) {
					l.addToken("DIRECTIVE", word)
					// Leer el resto de la línea como valor
					value := l.readRestOfLine()
					if value != "" {
						l.addToken("VALUE", value)
					}
				} else {
					l.addToken("WORD", word)
				}
			} else if isDigit(ch) {
				number := l.readWord()
				l.addToken("NUMBER", number)
			} else if ch == '/' || ch == '\\' {
				path := l.readPath()
				l.addToken("PATH", path)
			} else if ch == '$' {
				l.advance()
				if l.peek() == '{' {
					l.advance()
					var varName strings.Builder
					for l.peek() != 0 && l.peek() != '}' {
						varName.WriteByte(l.advance())
					}
					if l.peek() == '}' {
						l.advance()
						l.addToken("VARIABLE", varName.String())
					} else {
						l.addError("Unterminated variable")
					}
				} else {
					l.addError("Invalid variable syntax")
				}
			} else {
				if !isValidChar(ch) {
					l.addError(fmt.Sprintf("Invalid character: %c", ch))
				}
				l.advance()
			}
		}
	}

	return l.tokens, l.errors
}

// Analizador sintáctico
type Parser struct {
	tokens   []Token
	position int
	errors   []Error
	vhosts   []VirtualHost
}

func NewParser(tokens []Token) *Parser {
	return &Parser{
		tokens: tokens,
		errors: []Error{},
		vhosts: []VirtualHost{},
	}
}

func (p *Parser) addError(message, suggestion string, line, column int) {
	p.errors = append(p.errors, Error{
		Type:       "syntactic",
		Message:    message,
		Line:       line,
		Column:     column,
		Severity:   "error",
		Suggestion: suggestion,
	})
}

func (p *Parser) peek() *Token {
	if p.position >= len(p.tokens) {
		return nil
	}
	return &p.tokens[p.position]
}

func (p *Parser) advance() *Token {
	if p.position >= len(p.tokens) {
		return nil
	}
	token := &p.tokens[p.position]
	p.position++
	return token
}

func (p *Parser) skipComments() {
	for p.peek() != nil && p.peek().Type == "COMMENT" {
		p.advance()
	}
}

func (p *Parser) Parse() ([]VirtualHost, []Error) {
	for p.position < len(p.tokens) {
		p.skipComments()
		
		token := p.peek()
		if token == nil {
			break
		}

		if token.Type == "OPEN_TAG" && token.Value == "VirtualHost" {
			p.parseVirtualHost()
		} else {
			p.advance()
		}
	}

	return p.vhosts, p.errors
}

func (p *Parser) parseVirtualHost() {
	openTag := p.advance()

	var vhost VirtualHost
	vhost.Line = openTag.Line
	vhost.Directives = make(map[string]string)

	// Parse VirtualHost parameters
	paramsToken := p.peek()
	if paramsToken != nil && paramsToken.Type == "TAG_PARAMS" {
		params := p.advance()
		parts := strings.Split(params.Value, ":")
		if len(parts) == 2 {
			vhost.Address = strings.TrimSpace(parts[0])
			vhost.Port = strings.TrimSpace(parts[1])
		} else {
			vhost.Address = strings.TrimSpace(params.Value)
		}
	}

	// Parse directives inside VirtualHost
	for p.position < len(p.tokens) {
		p.skipComments()
		
		token := p.peek()
		if token == nil {
			p.addError("Unterminated VirtualHost block", "Add </VirtualHost> to close the block", openTag.Line, openTag.Column)
			break
		}

		if token.Type == "CLOSE_TAG" && token.Value == "VirtualHost" {
			p.advance()
			break
		}

		if token.Type == "DIRECTIVE" {
			directive := p.advance()
			
			// Buscar el valor correspondiente
			var value string
			valueToken := p.peek()
			if valueToken != nil && valueToken.Type == "VALUE" {
				value = p.advance().Value
			} else {
				p.addError(fmt.Sprintf("Missing value for directive: %s", directive.Value), "Add a value after the directive", directive.Line, directive.Column)
				continue
			}

			// Almacenar la directiva
			switch directive.Value {
			case "ServerName":
				vhost.ServerName = value
			case "DocumentRoot":
				vhost.DocumentRoot = value
			case "ErrorLog":
				vhost.ErrorLog = value
			case "AccessLog", "CustomLog":
				vhost.AccessLog = value
			default:
				vhost.Directives[directive.Value] = value
			}
		} else {
			p.advance()
		}
	}

	p.vhosts = append(p.vhosts, vhost)
}

// Analizador semántico mejorado
type SemanticAnalyzer struct {
	vhosts         []VirtualHost
	errors         []Error
	validateFiles  bool
	serverBasePath string
}

func NewSemanticAnalyzer(vhosts []VirtualHost, validateFiles bool, serverBasePath string) *SemanticAnalyzer {
	return &SemanticAnalyzer{
		vhosts:         vhosts,
		errors:         []Error{},
		validateFiles:  validateFiles,
		serverBasePath: serverBasePath,
	}
}

func (s *SemanticAnalyzer) addError(message, suggestion string, line int) {
	s.errors = append(s.errors, Error{
		Type:       "semantic",
		Message:    message,
		Line:       line,
		Severity:   "error",
		Suggestion: suggestion,
	})
}

func (s *SemanticAnalyzer) addWarning(message, suggestion string, line int) {
	s.errors = append(s.errors, Error{
		Type:       "semantic",
		Message:    message,
		Line:       line,
		Severity:   "warning",
		Suggestion: suggestion,
	})
}

func (s *SemanticAnalyzer) Analyze() []Error {
	s.checkDuplicateVirtualHosts()
	s.checkMissingDirectives()
	s.checkInvalidPorts()
	s.checkPathsExist()
	s.checkSSLConfiguration()

	return s.errors
}

func (s *SemanticAnalyzer) checkDuplicateVirtualHosts() {
	seen := make(map[string][]int)

	for i, vhost := range s.vhosts {
		key := fmt.Sprintf("%s:%s:%s", vhost.Address, vhost.Port, vhost.ServerName)
		seen[key] = append(seen[key], i)
	}

	for key, indices := range seen {
		if len(indices) > 1 {
			for _, idx := range indices {
				s.addWarning(
					fmt.Sprintf("Potential duplicate VirtualHost configuration: %s", key),
					"Ensure each VirtualHost has unique address:port:servername combination",
					s.vhosts[idx].Line,
				)
			}
		}
	}
}

func (s *SemanticAnalyzer) checkMissingDirectives() {
	for _, vhost := range s.vhosts {
		if vhost.DocumentRoot == "" {
			s.addWarning(
				"Missing DocumentRoot directive",
				"Add DocumentRoot directive to specify the document root directory",
				vhost.Line,
			)
		}

		if vhost.ServerName == "" {
			s.addWarning(
				"Missing ServerName directive",
				"Add ServerName directive to specify the server name",
				vhost.Line,
			)
		}
	}
}

func (s *SemanticAnalyzer) checkInvalidPorts() {
	for _, vhost := range s.vhosts {
		if vhost.Port != "" {
			if port, err := strconv.Atoi(vhost.Port); err != nil {
				s.addError(
					fmt.Sprintf("Invalid port number: %s", vhost.Port),
					"Port must be a valid number between 1 and 65535",
					vhost.Line,
				)
			} else if port < 1 || port > 65535 {
				s.addError(
					fmt.Sprintf("Port out of range: %d", port),
					"Port must be between 1 and 65535",
					vhost.Line,
				)
			}
		}
	}
}

func (s *SemanticAnalyzer) checkPathsExist() {
	// Solo verificar rutas si está habilitado y tenemos rutas para verificar
	if !s.validateFiles {
		return
	}

	for _, vhost := range s.vhosts {
		if vhost.DocumentRoot != "" {
			pathToCheck := vhost.DocumentRoot
			
			// Si tenemos una ruta base del servidor, construir la ruta completa
			if s.serverBasePath != "" {
				pathToCheck = filepath.Join(s.serverBasePath, strings.TrimPrefix(vhost.DocumentRoot, "/"))
			}
			
			// Solo verificar si la ruta parece ser local (no empieza con rutas típicas de servidor)
			if s.shouldValidatePath(vhost.DocumentRoot) && !pathExists(pathToCheck) {
				s.addWarning(
					fmt.Sprintf("DocumentRoot path may not exist: %s", vhost.DocumentRoot),
					"Ensure the DocumentRoot directory exists and is accessible on the target server",
					vhost.Line,
				)
			}
		}
		
		// Verificar rutas de logs solo si están en ubicaciones no estándar
		if vhost.ErrorLog != "" && s.shouldValidateLogPath(vhost.ErrorLog) {
			pathToCheck := vhost.ErrorLog
			if s.serverBasePath != "" {
				pathToCheck = filepath.Join(s.serverBasePath, strings.TrimPrefix(vhost.ErrorLog, "/"))
			}
			
			if !pathExists(filepath.Dir(pathToCheck)) {
				s.addWarning(
					fmt.Sprintf("ErrorLog directory may not exist: %s", filepath.Dir(vhost.ErrorLog)),
					"Ensure the log directory exists and is writable on the target server",
					vhost.Line,
				)
			}
		}
	}
}

func (s *SemanticAnalyzer) shouldValidatePath(path string) bool {
	// No validar rutas típicas de servidor que probablemente existan
	standardPaths := []string{
		"/var/www",
		"/usr/share/",
		"/opt/",
		"/srv/",
		"/home/",
		"C:\\inetpub\\",
		"C:\\Apache",
	}
	
	for _, stdPath := range standardPaths {
		if strings.HasPrefix(path, stdPath) {
			return false
		}
	}
	
	return true
}

func (s *SemanticAnalyzer) shouldValidateLogPath(path string) bool {
	// No validar rutas de logs estándar
	standardLogPaths := []string{
		"/var/log/",
		"/var/logs/",
		"/usr/local/apache2/logs/",
		"/etc/httpd/logs/",
		"C:\\Apache\\logs\\",
	}
	
	for _, stdPath := range standardLogPaths {
		if strings.HasPrefix(path, stdPath) {
			return false
		}
	}
	
	return true
}

func (s *SemanticAnalyzer) checkSSLConfiguration() {
	for _, vhost := range s.vhosts {
		if vhost.Port == "443" {
			sslEngine := vhost.Directives["SSLEngine"]
			if sslEngine == "" {
				s.addWarning(
					"SSL port 443 used without SSLEngine directive",
					"Add SSLEngine On directive for SSL VirtualHost",
					vhost.Line,
				)
			}
			
			if strings.ToLower(sslEngine) == "on" {
				if vhost.Directives["SSLCertificateFile"] == "" {
					s.addWarning(
						"SSL enabled but no SSLCertificateFile specified",
						"Add SSLCertificateFile directive for SSL certificate",
						vhost.Line,
					)
				}
				
				if vhost.Directives["SSLCertificateKeyFile"] == "" {
					s.addWarning(
						"SSL enabled but no SSLCertificateKeyFile specified",
						"Add SSLCertificateKeyFile directive for SSL private key",
						vhost.Line,
					)
				}
			}
		}
	}
}

// Funciones auxiliares
func isLetter(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isValidChar(ch byte) bool {
	return isLetter(ch) || isDigit(ch) || ch == '_' || ch == '-' || ch == '.' || ch == '/' || ch == ':' || ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func isValidDirective(word string) bool {
	validDirectives := []string{
		// Directivas básicas
		"ServerName", "DocumentRoot", "ErrorLog", "AccessLog", "CustomLog",
		"Directory", "DirectoryIndex", "AllowOverride", "Options", "Require",
		"LoadModule", "Listen", "ServerRoot", "PidFile", "Timeout",
		"KeepAlive", "MaxKeepAliveRequests", "KeepAliveTimeout",
		
		// Directivas SSL
		"SSLEngine", "SSLCertificateFile", "SSLCertificateKeyFile",
		"SSLCertificateChainFile", "SSLCACertificateFile", "SSLProtocol",
		"SSLCipherSuite", "SSLHonorCipherOrder", "SSLOptions",
		
		// Directivas de reescritura
		"RewriteEngine", "RewriteRule", "RewriteCond", "RewriteBase",
		
		// Directivas de proxy
		"ProxyPass", "ProxyPassReverse", "ProxyPreserveHost",
		
		// Directivas de headers
		"Header", "RequestHeader",
		
		// Directivas de compresión
		"SetOutputFilter", "SetInputFilter",
		
		// Otras directivas comunes
		"Alias", "ScriptAlias", "Redirect", "RedirectMatch",
		"DirectorySlash", "FileETag", "TraceEnable",
	}

	for _, directive := range validDirectives {
		if strings.EqualFold(word, directive) {
			return true
		}
	}
	
	return false
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// Handlers HTTP
func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	var req AnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Valores por defecto
	if req.ServerBasePath == "" {
		req.ServerBasePath = ""
	}

	// Análisis léxico
	lexer := NewLexer(req.Content)
	tokens, lexicalErrors := lexer.Tokenize()

	// Análisis sintáctico
	parser := NewParser(tokens)
	vhosts, syntacticErrors := parser.Parse()

	// Análisis semántico con nuevas opciones
	semanticAnalyzer := NewSemanticAnalyzer(vhosts, req.ValidateFiles, req.ServerBasePath)
	semanticErrors := semanticAnalyzer.Analyze()

	// Combinar errores
	allErrors := append(lexicalErrors, syntacticErrors...)
	allErrors = append(allErrors, semanticErrors...)

	// Crear resumen
	summary := Summary{
		TotalLines:      len(strings.Split(req.Content, "\n")),
		VirtualHosts:    len(vhosts),
		LexicalErrors:   len(lexicalErrors),
		SyntacticErrors: len(syntacticErrors),
		SemanticErrors:  len(semanticErrors),
	}

	result := AnalysisResult{
		Tokens:       tokens,
		Errors:       allErrors,
		VirtualHosts: vhosts,
		Summary:      summary,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	r := mux.NewRouter()

	// Configurar CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173", "http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	// Rutas
	r.HandleFunc("/analyze", analyzeHandler).Methods("POST")

	// Aplicar CORS
	handler := c.Handler(r)

	fmt.Println("Servidor iniciado en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}