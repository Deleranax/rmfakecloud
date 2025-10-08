package ui

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ddvk/rmfakecloud/internal/app/oidcstate"
	"github.com/ddvk/rmfakecloud/internal/common"
	"github.com/ddvk/rmfakecloud/internal/integrations"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/ddvk/rmfakecloud/internal/storage"
	"github.com/ddvk/rmfakecloud/internal/storage/models"
	"github.com/ddvk/rmfakecloud/internal/ui/viewmodel"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

const (
	userIDContextKey    = "userID"
	browserIDContextKey = "browserID"
	isSync15Key         = "sync15"
	docIDParam          = "docid"
	intIDParam          = "intid"
	uiLogger            = "[ui] "
	ui10                = " [10] "
	useridParam         = "userid"
	cookieName          = ".Authrmfakecloud"
	oidcStateCookieName = ".OIDCState"
)

func userID(c *gin.Context) string {
	//TODO: suppress the warning
	//codeql[go/path-injection]
	return c.GetString(userIDContextKey)
}

func (app *ReactAppWrapper) register(c *gin.Context) {

	if !app.cfg.RegistrationOpen {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	client := c.ClientIP()
	log.Info(client)

	if client != "localhost" &&
		client != "::1" &&
		client != "127.0.0.1" {
		c.AbortWithStatusJSON(http.StatusForbidden, viewmodel.NewErrorResponse("Registrations are closed"))
		return
	}

	var form viewmodel.LoginForm
	if err := c.ShouldBindJSON(&form); err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// Check this user doesn't already exist
	_, err := app.userStorer.GetUser(form.Email)
	if err == nil {
		badReq(c, "already taken")
		return
	}

	user, err := model.NewUser(form.Email, form.Password)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	err = app.userStorer.RegisterUser(user)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, user)
}

// loginWith login with email and password as strings
func (app *ReactAppWrapper) loginWith(c *gin.Context, oidc bool, email string, password string) {
	// Generate random password
	if oidc {
		newPassword, err := model.GenPassword()
		if err != nil {
			log.Error("[login]", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		password = newPassword
	}

	// not really thread safe
	if app.cfg.CreateFirstUser {
		log.Info("Creating an admin user")

		if oidc {
			log.Info("Assigning random password (to allow login without OIDC)")
		}

		user, err := model.NewUser(email, password)
		if err != nil {
			log.Error("[login]", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		user.IsAdmin = true
		err = app.userStorer.RegisterUser(user)
		if err != nil {
			log.Error("[login] Register ", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		app.cfg.CreateFirstUser = false
	}

	// Try to find the user
	user, err := app.userStorer.GetUser(email)
	if err != nil {
		if app.cfg.RegistrationOpen && oidc {
			log.Info("Registering new user " + email + " with OIDC")
			log.Info("Assigning random password (to allow login without OIDC)")

			newUser, err := model.NewUser(email, password)
			if err != nil {
				log.Error("[login]", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			err = app.userStorer.RegisterUser(newUser)
			if err != nil {
				log.Error(err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			user = newUser
		} else {
			log.Error(uiLogger, err, " cannot load user, login failed ip: ", c.ClientIP())
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}

	if !oidc {
		if ok, err := user.CheckPassword(password); err != nil || !ok {
			if err != nil {
				log.Error(err)
			} else if !ok {
				log.Warn(uiLogger, "wrong password for: ", email, ", login failed ip: ", c.ClientIP())
			}
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}

	scopes := ""
	if user.Sync15 {
		scopes = isSync15Key
	}
	expiresAfter := 24 * time.Hour
	expires := time.Now().Add(expiresAfter)
	claims := &WebUserClaims{
		UserID:    user.ID,
		BrowserID: uuid.NewString(),
		Email:     user.Email,
		Scopes:    scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			Issuer:    "rmFake WEB",
			Audience:  []string{WebUsage},
		},
	}
	if user.IsAdmin {
		claims.Roles = []string{AdminRole}
	} else {
		claims.Roles = []string{"User"}
	}

	tokenString, err := common.SignClaims(claims, app.cfg.JWTSecretKey)

	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	log.Debug("cookie expires after: ", expiresAfter)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(cookieName, tokenString, int(expiresAfter.Seconds()), "/", "", app.cfg.HTTPSCookie, true)

	c.String(http.StatusOK, tokenString)
}

func (app *ReactAppWrapper) login(c *gin.Context) {
	if app.cfg.OIDCConfig != nil {
		if app.cfg.OIDCConfig.Only {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}

	var form viewmodel.LoginForm
	if err := c.ShouldBindJSON(&form); err != nil {
		log.Error(uiLogger, err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	app.loginWith(c, false, form.Email, form.Password)
}

func (app *ReactAppWrapper) oidcInfo(c *gin.Context) {
	if app.cfg.OIDCConfig != nil {
		c.JSON(http.StatusOK, viewmodel.OIDCInfo{
			Enabled: true,
			Label:   app.cfg.OIDCConfig.Label,
			Only:    app.cfg.OIDCConfig.Only,
		})
	} else {
		c.JSON(http.StatusOK, viewmodel.OIDCInfo{
			Enabled: false,
			Label:   "",
			Only:    false,
		})
	}
}

func (app *ReactAppWrapper) oidcAuth(c *gin.Context) {
	log.Info("OIDC authentication started")
	if app.cfg.OIDCConfig == nil {
		log.Warn("OIDC configuration is missing")
		oidcError(c, "OIDC configuration is missing", "OIDC authentication is not configured")
		return
	}
	if app.cfg.OIDCConfig.ConfigURL == "" {
		log.Warn("OIDC issuer URL is empty")
		oidcError(c, "OIDC issuer URL is empty", "OIDC authentication is misconfigured")
		return
	}
	if app.cfg.OIDCConfig.ClientID == "" {
		log.Warn("OIDC client ID is empty")
		oidcError(c, "OIDC client ID is empty", "OIDC authentication is misconfigured")
		return
	}

	_, oauthConfig, err := app.oidcConfig(c)
	if err != nil {
		oidcError(c, err, "Unable to initialize OIDC authentication. Check the server configuration")
		return
	}

	state, err := app.oidcStateStore.Create()
	if err != nil {
		oidcError(c, err, "Unable to start OIDC authentication")
		return
	}
	log.WithField("state_id", oidcStateID(state)).Info("OIDC authentication state created")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oidcStateCookieName, state, int(oidcstate.StateTTL.Seconds()), "/", "", app.cfg.HTTPSCookie, true)
	c.String(http.StatusOK, oauthConfig.AuthCodeURL(state))
}

func (app *ReactAppWrapper) oidcConfig(c *gin.Context) (*oidc.Provider, *oauth2.Config, error) {
	app.oidcMu.Lock()
	defer app.oidcMu.Unlock()

	if app.oidcProvider != nil && app.oauth2Config != nil {
		return app.oidcProvider, app.oauth2Config, nil
	}

	log.WithField("issuer", app.cfg.OIDCConfig.ConfigURL).Debug("OIDC provider discovery started")
	provider, err := oidc.NewProvider(c, app.cfg.OIDCConfig.ConfigURL)
	if err != nil {
		return nil, nil, err
	}
	log.Debug("OIDC provider discovery succeeded")

	oauthConfig := &oauth2.Config{
		ClientID:     app.cfg.OIDCConfig.ClientID,
		ClientSecret: app.cfg.OIDCConfig.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  app.cfg.StorageURL + "/login",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	log.WithField("redirect_url", oauthConfig.RedirectURL).Debug("OIDC OAuth2 configuration initialized")
	app.oidcProvider = provider
	app.oauth2Config = oauthConfig
	return provider, oauthConfig, nil
}

func (app *ReactAppWrapper) oidcCallback(c *gin.Context) {
	log.Info("OIDC callback received")
	if app.cfg.OIDCConfig == nil {
		log.Warn("OIDC configuration is missing during callback")
		oidcError(c, "OIDC configuration is missing", "OIDC authentication is not configured")
		return
	}
	if app.cfg.OIDCConfig.ClientID == "" {
		log.Warn("OIDC client ID is empty during callback")
		oidcError(c, "OIDC client ID is empty", "OIDC authentication is misconfigured")
		return
	}
	provider, oauthConfig, err := app.oidcConfig(c)
	if err != nil {
		oidcError(c, err, "OIDC authentication is not initialized")
		return
	}

	var req viewmodel.OIDCCallback

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error(err)
		badReq(c, err.Error())
		return
	}
	log.WithFields(log.Fields{
		"has_code": req.Code != "",
		"state_id": oidcStateID(req.State),
	}).Debug("OIDC callback payload parsed")

	if req.State == "" {
		oidcErrorStatus(c, "OIDC callback did not include a state", "OIDC authentication response is invalid", http.StatusBadRequest)
		return
	}
	cookieState, err := c.Cookie(oidcStateCookieName)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookieState), []byte(req.State)) != 1 {
		oidcErrorStatus(c, "OIDC callback state does not match the browser state", "OIDC authentication session is invalid", http.StatusBadRequest)
		return
	}
	if err := app.oidcStateStore.Consume(req.State); err != nil {
		oidcErrorStatus(c, err, "OIDC authentication session expired or is invalid", http.StatusBadRequest)
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oidcStateCookieName, "", -1, "/", "", app.cfg.HTTPSCookie, true)
	log.WithField("state_id", oidcStateID(req.State)).Info("OIDC authentication state validated")

	log.Debug("OIDC ID token verifier initialization started")
	verifier := provider.Verifier(&oidc.Config{ClientID: app.cfg.OIDCConfig.ClientID})

	// Verify state and errors.
	log.Debug("OIDC authorization code exchange started")
	oauth2Token, err := oauthConfig.Exchange(c, req.Code)
	if err != nil {
		oidcError(c, err, "OIDC authentication failed")
		return
	}
	log.Debug("OIDC authorization code exchange succeeded")

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		oidcError(c, "OIDC token did not contain an ID token", "OIDC authentication failed")
		return
	}
	log.Debug("OIDC ID token extracted")

	// Parse and verify ID Token payload.
	log.Debug("OIDC ID token verification started")
	idToken, err := verifier.Verify(c, rawIDToken)
	if err != nil {
		oidcError(c, err, "OIDC authentication failed")
		return
	}
	log.Debug("OIDC ID token verification succeeded")

	// Extract custom claims
	var oidcClaims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Subject           string `json:"sub"`
	}
	if err := idToken.Claims(&oidcClaims); err != nil {
		oidcError(c, err, "OIDC authentication failed")
		return
	}
	log.WithFields(log.Fields{
		"email_present":              oidcClaims.Email != "",
		"preferred_username_present": oidcClaims.PreferredUsername != "",
		"subject_present":            oidcClaims.Subject != "",
	}).Info("OIDC ID token claims extracted")

	if oidcClaims.Email == "" {
		log.Debug("OIDC email claim missing, requesting user info")
		userInfo, err := provider.UserInfo(c, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			oidcError(c, err, "OIDC provider did not provide a usable user identity")
			return
		}

		var userInfoClaims struct {
			Email string `json:"email"`
		}
		if err := userInfo.Claims(&userInfoClaims); err != nil {
			oidcError(c, err, "OIDC provider did not provide a usable user identity")
			return
		}
		oidcClaims.Email = userInfoClaims.Email
		log.WithField("email_present", oidcClaims.Email != "").Info("OIDC user info claims extracted")
	}

	if oidcClaims.Email == "" {
		oidcError(c, "OIDC identity does not contain an email claim", "OIDC provider did not provide a usable user identity")
		return
	}

	app.loginWith(c, true, model.SanitizeEmail(oidcClaims.Email), "")
}

func oidcStateID(state string) string {
	if state == "" {
		return "<empty>"
	}
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])[:12]
}

func (app *ReactAppWrapper) changePassword(c *gin.Context) {
	var req viewmodel.ResetPasswordForm

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error(err)
		badReq(c, err.Error())
		return
	}

	user, err := app.userStorer.GetUser(req.UserID)

	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	uid := userID(c)

	if user.ID != uid {
		log.Error("Trying to change password for a different user.")
		c.AbortWithStatusJSON(http.StatusBadRequest, viewmodel.NewErrorResponse("cant do that"))
		return
	}

	ok, err := user.CheckPassword(req.CurrentPassword)
	if !ok {
		if err != nil {
			log.Error(err)
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, viewmodel.NewErrorResponse("Invalid email or password"))
		return
	}

	if req.NewPassword != "" {
		user.SetPassword(req.NewPassword)
	}

	err = app.userStorer.UpdateUser(user)

	if err != nil {
		log.Error("error updating user", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (app *ReactAppWrapper) newCode(c *gin.Context) {
	uid := userID(c)

	user, err := app.userStorer.GetUser(uid)
	if err != nil {
		log.Error("Unable to find user: ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, viewmodel.NewErrorResponse(err.Error()))
		return
	}

	code, err := app.codeConnector.NewCode(user.ID)
	if err != nil {
		log.Error("Unable to generate new device code: ", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, viewmodel.NewErrorResponse("Unable to generate new code"))
		return
	}

	c.JSON(http.StatusOK, code)
}

func (app *ReactAppWrapper) getBackend(c *gin.Context) backend {
	s, ok := c.Get(backendVersionKey)
	if !ok {
		panic("key not set")
	}
	backend, ok := app.backends[s.(common.SyncVersion)]
	if !ok {
		panic("backend not found")
	}
	return backend
}

func (app *ReactAppWrapper) listDocuments(c *gin.Context) {
	uid := userID(c)

	var tree *viewmodel.DocumentTree

	backend := app.getBackend(c)
	tree, err := backend.GetDocumentTree(uid)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, tree)
}
func (app *ReactAppWrapper) getDocument(c *gin.Context) {
	uid := userID(c)
	docid := common.ParamS(docIDParam, c)

	exportType := c.DefaultQuery("type", "pdf")
	var exportOption storage.ExportOption = 0

	log.Info("exporting ", docid, " as ", exportType)
	backend := app.getBackend(c)

	reader, err := backend.Export(uid, docid, exportType, exportOption)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	defer reader.Close()

	if exportType == "rmdoc" {
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.rmdoc\"", docid))
	}

	c.DataFromReader(http.StatusOK, -1, "application/octet-stream", reader, nil)
}

func (app *ReactAppWrapper) getDocumentMetadata(c *gin.Context) {
	uid := userID(c)
	docid := common.ParamS(docIDParam, c)
	// if err != nil {
	// 	log.Error(err)
	// 	c.AbortWithStatus(http.StatusInternalServerError)
	// 	return
	// }
	log.Info(uid, docid)
	c.JSON(http.StatusOK, "TODO")

}

// move rename
func (app *ReactAppWrapper) updateDocument(c *gin.Context) {
	upd := viewmodel.UpdateDoc{}
	if err := c.ShouldBindJSON(&upd); err != nil {
		log.Error(err)
		badReq(c, err.Error())
		return
	}
	backend := app.getBackend(c)
	uid := userID(c)
	log.Info(uiLogger, ui10, "updatedoc")
	err := backend.UpdateDocument(uid, upd.DocumentID, upd.Name, upd.ParentID)
	if err != nil {
		badReq(c, err.Error())
		return
	}

	c.Status(http.StatusOK)
}
func (app *ReactAppWrapper) deleteDocument(c *gin.Context) {
	uid := userID(c)
	docid := c.Param("docid")
	backend := app.getBackend(c)

	err := backend.DeleteDocument(uid, docid)
	if err != nil {
		badReq(c, err.Error())
	}
	c.Status(http.StatusOK)
}

func (app *ReactAppWrapper) createFolder(c *gin.Context) {
	upd := viewmodel.NewFolder{}
	if err := c.ShouldBindJSON(&upd); err != nil {
		log.Error(err)
		badReq(c, err.Error())
		return
	}
	uid := userID(c)

	backend := app.getBackend(c)

	doc, err := backend.CreateFolder(uid, upd.Name, upd.ParentID)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, doc)
}

func (app *ReactAppWrapper) createDocument(c *gin.Context) {
	uid := userID(c)
	log.Info("uploading documents from: ", uid)

	backend := app.getBackend(c)

	form, err := c.MultipartForm()
	if err != nil {
		log.Error(err)
		badReq(c, "not multiform")
		return
	}
	parentID := ""
	if parent, ok := form.Value["parent"]; ok {
		if parent[0] != "root" {
			parentID = parent[0]
		}
	}

	log.Info("Parent: " + parentID)

	docs := []*storage.Document{}
	for _, file := range form.File["file"] {
		f, err := file.Open()
		if err != nil {
			log.Error("[ui] ", err)
			badReq(c, "cant open attachment")
			return
		}

		defer f.Close()
		//do the stuff
		log.Info(uiLogger, fmt.Sprintf("Uploading %s , size: %d", file.Filename, file.Size))

		doc, err := backend.CreateDocument(uid, file.Filename, parentID, f)
		if err != nil {
			var existsErr *models.ErrDocumentExists
			if errors.As(err, &existsErr) {
				c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error(), "docId": existsErr.DocID})
				return
			}
			log.Error(err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		docs = append(docs, doc)
	}
	backend.Sync(uid)
	c.JSON(http.StatusOK, docs)
}

func (app *ReactAppWrapper) getAppUsers(c *gin.Context) {
	// Try to find the user
	users, err := app.userStorer.GetUsers()

	if err != nil {
		log.Error(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, viewmodel.NewErrorResponse("Unable to get users."))
		return
	}

	uilist := make([]viewmodel.User, 0)
	for _, u := range users {
		usr := viewmodel.User{
			ID:        u.ID,
			Email:     u.Email,
			Name:      u.Name,
			CreatedAt: u.CreatedAt,
			IsAdmin:   u.IsAdmin,
		}
		uilist = append(uilist, usr)
	}
	c.JSON(http.StatusOK, uilist)
}

func (app *ReactAppWrapper) getUser(c *gin.Context) {
	uid := c.Param(useridParam)
	log.Info("Requested: ", uid)

	// Try to find the user
	user, err := app.userStorer.GetUser(uid)
	if err != nil {
		log.Error(err)
		badReq(c, err.Error())
		return
	}

	if user == nil {
		c.AbortWithStatusJSON(http.StatusNotFound, "Invalid user")
		return
	}
	if uid != user.ID && !IsAdmin(c) {
		log.Warn("Only admins can query other users")
		c.AbortWithStatusJSON(http.StatusUnauthorized, "")
		return
	}

	vmUser := &viewmodel.User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		CreatedAt: user.CreatedAt,
	}
	for _, i := range user.Integrations {
		vmUser.Integrations = append(vmUser.Integrations, i.Name)
	}

	c.JSON(http.StatusOK, vmUser)
}

func (app *ReactAppWrapper) updateUser(c *gin.Context) {
	var req viewmodel.User
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	user, err := app.userStorer.GetUser(req.ID)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if user == nil {
		c.AbortWithStatusJSON(http.StatusNotFound, "Invalid user")
		return
	}
	if req.NewPassword != "" {
		user.SetPassword(req.NewPassword)
	}

	if req.Email != "" {
		user.Email = req.Email
	}

	err = app.userStorer.UpdateUser(user)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusAccepted)
}
func (app *ReactAppWrapper) deleteUser(c *gin.Context) {
	uid := c.Param(useridParam)
	if uid == userID(c) {
		log.Error("can't remove current user ")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	err := app.userStorer.RemoveUser(uid)
	if err != nil {
		log.Error("can't remove ", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusAccepted)
}

func (app *ReactAppWrapper) createUser(c *gin.Context) {
	var req viewmodel.NewUser
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error(err)
		badReq(c, err.Error())
		return
	}

	user, err := model.NewUser(req.ID, req.NewPassword)

	if err != nil {
		log.Error("can't create ", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	user.Email = req.Email

	err = app.userStorer.UpdateUser(user)
	if err != nil {
		log.Error("can't create ", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusCreated)
}

func (app *ReactAppWrapper) listIntegrations(c *gin.Context) {
	uid := userID(c)

	user, err := app.userStorer.GetUser(uid)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	c.JSON(http.StatusOK, user.Integrations)
}

func warnLocalfsEdition(c *gin.Context, int *model.IntegrationConfig) {
	s, err := yaml.Marshal(gin.H{"integrations": []*model.IntegrationConfig{int}})
	if err != nil {
		log.Error("error updating user", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.AbortWithStatusJSON(http.StatusForbidden,
		viewmodel.NewErrorResponse("To avoid security issues with local directory integration, you have to manually edit your .userprofile file:\n\n"+string(s)))
}

func (app *ReactAppWrapper) createIntegration(c *gin.Context) {
	int := model.IntegrationConfig{}
	if err := c.ShouldBindJSON(&int); err != nil {
		log.Error(err)
		badReq(c, err.Error())
		return
	}

	if int.Provider == integrations.LocalfsProvider {
		int.ID = uuid.NewString()
		warnLocalfsEdition(c, &int)
		return
	}

	uid := userID(c)

	user, err := app.userStorer.GetUser(uid)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	int.ID = uuid.NewString()
	user.Integrations = append(user.Integrations, int)

	err = app.userStorer.UpdateUser(user)

	if err != nil {
		log.Error("error updating user", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, int)
}

func (app *ReactAppWrapper) getIntegration(c *gin.Context) {
	uid := userID(c)

	intid := common.ParamS(intIDParam, c)

	user, err := app.userStorer.GetUser(uid)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	for _, integration := range user.Integrations {
		if integration.ID == intid {
			c.JSON(http.StatusOK, integration)
			return
		}
	}

	c.AbortWithStatus(http.StatusNotFound)
}

func (app *ReactAppWrapper) updateIntegration(c *gin.Context) {
	int := model.IntegrationConfig{}
	if err := c.ShouldBindJSON(&int); err != nil {
		log.Error(err)
		badReq(c, err.Error())
		return
	}

	if int.Provider == integrations.LocalfsProvider {
		warnLocalfsEdition(c, &int)
		return
	}

	uid := userID(c)

	intid := common.ParamS(intIDParam, c)

	user, err := app.userStorer.GetUser(uid)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	for idx, integration := range user.Integrations {
		if integration.ID == intid {
			int.ID = integration.ID
			user.Integrations[idx] = int

			err = app.userStorer.UpdateUser(user)

			if err != nil {
				log.Error("error updating user", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			c.JSON(http.StatusOK, int)
			return
		}
	}

	c.AbortWithStatus(http.StatusNotFound)
}

func (app *ReactAppWrapper) deleteIntegration(c *gin.Context) {
	uid := userID(c)

	intid := common.ParamS(intIDParam, c)

	user, err := app.userStorer.GetUser(uid)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	for idx, integration := range user.Integrations {
		if integration.ID == intid {
			user.Integrations = append(user.Integrations[:idx], user.Integrations[idx+1:]...)

			err = app.userStorer.UpdateUser(user)

			if err != nil {
				log.Error("error updating user", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			c.Status(http.StatusAccepted)
			return
		}
	}

	c.AbortWithStatus(http.StatusNotFound)
}

func (app *ReactAppWrapper) exploreIntegration(c *gin.Context) {
	uid := userID(c)

	integrationID := common.ParamS(intIDParam, c)

	integrationProvider, err := integrations.GetStorageIntegrationProvider(app.userStorer, uid, integrationID)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	folder := common.ParamS("path", c)
	if folder == "" {
		folder = "root"
	}

	response, err := integrationProvider.List(folder, 2)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, response)
}

func (app *ReactAppWrapper) getMetadataIntegration(c *gin.Context) {
	uid := userID(c)

	integrationID := common.ParamS(intIDParam, c)

	integrationProvider, err := integrations.GetStorageIntegrationProvider(app.userStorer, uid, integrationID)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	fileid := common.ParamS("path", c)

	response, err := integrationProvider.GetMetadata(fileid)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, response)
}

func (app *ReactAppWrapper) downloadThroughIntegration(c *gin.Context) {
	uid := userID(c)

	integrationID := common.ParamS(intIDParam, c)

	integrationProvider, err := integrations.GetStorageIntegrationProvider(app.userStorer, uid, integrationID)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	fileid := common.ParamS("path", c)

	response, size, err := integrationProvider.Download(fileid)
	if err != nil {
		log.Error(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	defer response.Close()

	c.DataFromReader(http.StatusOK, size, "", response, nil)
}

func (app *ReactAppWrapper) screenshareJoinActive(c *gin.Context) {
	uid := userID(c)

	roomID := app.roomManager.FindActiveRoom(uid)
	if roomID == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active room"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"roomId":     roomID,
		"clients":    app.roomManager.GetClients(roomID),
		"iceServers": app.cfg.ICEServers,
	})
}

func (app *ReactAppWrapper) screenshareGetRoom(c *gin.Context) {
	roomID := c.Param("roomId")

	room := app.roomManager.GetRoom(roomID)
	if room == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "room not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"roomId":    room.RoomID,
		"createdAt": room.CreatedAt.Format(time.RFC3339Nano),
		"clients":   app.roomManager.GetClients(roomID),
	})
}

func (app *ReactAppWrapper) screenshareGetOffer(c *gin.Context) {
	uid := userID(c)
	clientID := c.GetString(browserIDContextKey)

	roomID := app.roomManager.FindActiveRoom(uid)
	if roomID == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no active room"})
		return
	}

	app.roomManager.AddBroadcast(roomID, clientID, json.RawMessage(`{"type":"request-offer","clientId":"`+clientID+`"}`))

	var inner map[string]interface{}
	json.Unmarshal([]byte(`{"type":"request-offer","clientId":"`+clientID+`","sourceDeviceID":"`+clientID+`"}`), &inner)
	app.h.NotifyScreenshare(uid, clientID, inner)

	if app.mqtt != nil && app.mqtt.HasConnectedClient(uid) {
		clients := app.roomManager.GetClients(roomID)
		for _, cl := range clients {
			if cl.IsOwner {
				mqttMsg, _ := json.Marshal(map[string]interface{}{
					"type":     "broadcast",
					"clientId": clientID,
					"payload":  json.RawMessage(`{"type":"request-offer","clientId":"` + clientID + `"}`),
				})
				app.mqtt.PublishSignaling(uid, cl.ClientID, mqttMsg)
				break
			}
		}
	}

	msgs := app.roomManager.WaitForMessages(roomID, 1, 30*time.Second)
	if msgs == nil {
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "timeout waiting for offer"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"roomId":     roomID,
		"messages":   msgs,
		"iceServers": app.cfg.ICEServers,
	})
}

func (app *ReactAppWrapper) screenshareSendAnswer(c *gin.Context) {
	roomID := c.Param("roomId")
	clientID := c.GetString(browserIDContextKey)
	uid := userID(c)

	if !app.roomManager.RoomExists(roomID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "room not found"})
		return
	}

	var msg struct {
		Payload        json.RawMessage `json:"payload"`
		TargetClientID string          `json:"targetClientId"`
	}
	if err := c.ShouldBindJSON(&msg); err != nil {
		badReq(c, "invalid body")
		return
	}

	app.roomManager.AddDirect(roomID, clientID, msg.TargetClientID, msg.Payload)

	var inner map[string]interface{}
	json.Unmarshal(msg.Payload, &inner)
	inner["sourceDeviceID"] = clientID
	app.h.NotifyScreenshare(uid, clientID, inner)

	if app.mqtt != nil && app.mqtt.HasConnectedClient(uid) {
		mqttMsg, _ := json.Marshal(map[string]interface{}{
			"type":     "direct",
			"clientId": clientID,
			"payload":  json.RawMessage(msg.Payload),
		})
		app.mqtt.PublishSignaling(uid, msg.TargetClientID, mqttMsg)
	}

	c.Status(http.StatusAccepted)
}

func (app *ReactAppWrapper) screenshareDeleteRoom(c *gin.Context) {
	uid := userID(c)
	app.roomManager.DeleteAllForUser(uid)
	c.Status(http.StatusNoContent)
}
