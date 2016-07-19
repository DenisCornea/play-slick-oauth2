package controllers

import com.google.inject.Inject
import models.daos.{AccountsDAO, OauthAccessTokensDAO, OauthAuthorizationCodesDAO, OauthClientsDAO}
import models.entities.{Account, OauthAccessToken}
import play.api.libs.json.{JsString, JsValue, Json, Writes}
import play.api.mvc.{Action, Controller}
import scala.concurrent.Future
import scalaoauth2.provider._
import scalaoauth2.provider.OAuth2ProviderActionBuilders._
import play.api.Logger


class OAuthController  @Inject()(accountsDAO : AccountsDAO,
                                 oauthAuthorizationCodesDAO : OauthAuthorizationCodesDAO,
                                 oauthAccessTokensDAO : OauthAccessTokensDAO,
                                 oauthClientsDAO : OauthClientsDAO) extends Controller with OAuth2Provider {

  implicit val authInfoWrites = new Writes[AuthInfo[Account]] {
    def writes(authInfo: AuthInfo[Account]) = {
      Json.obj(
        "account" -> Json.obj(
          "email" -> authInfo.user.email
        ),
        "clientId" -> authInfo.clientId,
        "redirectUri" -> authInfo.redirectUri
      )
    }
  }

  override val tokenEndpoint = new TokenEndpoint {
    override val handlers = Map(
      OAuthGrantType.AUTHORIZATION_CODE -> new AuthorizationCode(),
      OAuthGrantType.REFRESH_TOKEN -> new RefreshToken(),
      OAuthGrantType.CLIENT_CREDENTIALS -> new ClientCredentials(),
      OAuthGrantType.PASSWORD -> new Password()
    )
  }

  def index = Action.async { implicit request =>
    Future.successful(
      Ok(Json.toJson(Map[String, JsValue]("welcome_message" -> JsString("Welcome!"))))
        .withHeaders("Cache-Control" -> "no-store", "Pragma" -> "no-cache"))
  }

  def access = Action.async { implicit request =>
       val result =  issueAccessToken(new MyDataHandler())
    Logger.error("Access result:  "+ result.map{_.toString()})
    result
  }


  def resources = AuthorizedAction(new MyDataHandler()) { request =>
    Ok(Json.toJson(request.authInfo))
  }

  def authorizationCode = Action.async { implicit request =>

    Logger.error("Request: " + request.toString + " with query string " + request.rawQueryString)
    val futureResult: Future[Either[OAuthError, String]] =
      accountsDAO.authenticate(
        request.getQueryString("username").getOrElse(""),
        request.getQueryString("password").getOrElse("")).flatMap {
        accountMaybe =>
          accountMaybe match {
            case Some(account) =>
              val clientFuture = oauthClientsDAO.findByClientId( request.getQueryString("client").getOrElse(""))
              clientFuture.flatMap { clientMaybe =>
                clientMaybe match {
                  case Some(client) =>
                    val futureCode = oauthAuthorizationCodesDAO.createCode(account.id, client.id, client.redirectUri)
                    futureCode.map(oauthCode => Right(oauthCode.code))
                  case None => Future.successful(Left(new InvalidClient("Invalid client is detected")))
                }
              }
            case None =>
              Future.successful(Left(new AccessDenied("Invalid username or password")))
          }
    }

    futureResult.map { result =>
      result match {
        case Left(e) =>
          Logger.error("Error authorization response " + e.description)
          new Status(e.statusCode)(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
        case Right(value) =>
          Logger.error("Authorization response - authorization_code: " + value)
          Ok(Json.toJson(Map[String, JsValue]("authorization_code" -> JsString(value)))).withHeaders("Cache-Control" -> "no-store", "Pragma" -> "no-cache")
      }
    }
  }

  class MyDataHandler extends DataHandler[Account] {

    override def validateClient(request: AuthorizationRequest): Future[Boolean] =  {
      request.clientCredential.fold(Future.successful(false))(clientCredential => oauthClientsDAO.validate(clientCredential.clientId,
        clientCredential.clientSecret.getOrElse(""), request.grantType))
    }

    override def getStoredAccessToken(authInfo: AuthInfo[Account]): Future[Option[AccessToken]] = {
      oauthAccessTokensDAO.findByAuthorized(authInfo.user, authInfo.clientId.getOrElse("")).map(_.map(toAccessToken))
    }

    private val accessTokenExpireSeconds = 3600
    private def toAccessToken(accessToken: OauthAccessToken) = {
      AccessToken(
        accessToken.accessToken,
        Some(accessToken.refreshToken),
        None,
        Some(accessTokenExpireSeconds),
        accessToken.createdAt
      )
    }
    override def createAccessToken(authInfo: AuthInfo[Account]): Future[AccessToken] = {
      authInfo.clientId.fold(Future.failed[AccessToken](new InvalidRequest()))
      { clientId =>
        (for {
          clientOpt <- oauthClientsDAO.findByClientId(clientId)
          toAccessToken <-  oauthAccessTokensDAO.create(authInfo.user, clientOpt.get).map(toAccessToken) if clientOpt.isDefined
        } yield toAccessToken).recover{case _ => throw new InvalidRequest()}
      }
    }



    override def findUser(request: AuthorizationRequest): Future[Option[Account]] =
      request match {
        case request: PasswordRequest =>
          accountsDAO.authenticate(request.username, request.password)
        case request: ClientCredentialsRequest =>
          request.clientCredential.fold(Future.failed[Option[Account]](new InvalidRequest())){ clientCredential =>
            for {
              maybeAccount <- oauthClientsDAO.findClientCredentials(
                clientCredential.clientId,
                clientCredential.clientSecret.getOrElse("")
              )
            } yield maybeAccount
          }
        case _ =>
          Future.successful(None)
      }

    override def findAuthInfoByRefreshToken(refreshToken: String): Future[Option[AuthInfo[Account]]] = {
      oauthAccessTokensDAO.findByRefreshToken(refreshToken).flatMap {
        case Some(accessToken) =>
          for {
            account <- accountsDAO.findById(accessToken.accountId)
            client <-  oauthClientsDAO.findById(accessToken.oauthClientId)
          } yield {
            Some(AuthInfo(
              user = account.get,
              clientId = Some(client.get.clientId),
              scope = None,
              redirectUri = None
            ))
          }
        case None => Future.failed(new InvalidRequest())
      }
    }

    override def refreshAccessToken(authInfo: AuthInfo[Account], refreshToken: String): Future[AccessToken] = {
      authInfo.clientId.fold(Future.failed[AccessToken](new InvalidRequest()))
      { clientId => (for {
        clientOpt <- oauthClientsDAO.findByClientId(clientId)
        toAccessToken <- oauthAccessTokensDAO.refresh(authInfo.user, clientOpt.get).map(toAccessToken) if clientOpt.isDefined
      } yield toAccessToken).recover { case _ => throw new InvalidClient()}}
    }

    override def findAuthInfoByCode(code: String): Future[Option[AuthInfo[Account]]] = {
      oauthAuthorizationCodesDAO.findByCode(code).flatMap {
        case Some(code) =>
          for {
            account <- accountsDAO.findById(code.accountId)
            client <-  oauthClientsDAO.findById(code.oauthClientId)
          } yield {
            Some(AuthInfo(
              user = account.get,
              clientId = Some(client.get.clientId),
              scope = None,
              redirectUri = None
            ))
          }
        case None => Future.failed(new InvalidRequest())
      }
    }

    override def deleteAuthCode(code: String): Future[Unit] = oauthAuthorizationCodesDAO.delete(code).map( _ => {})

    override def findAccessToken(token: String): Future[Option[AccessToken]] =
      oauthAccessTokensDAO.findByAccessToken(token).map(_.map(toAccessToken))

    override def findAuthInfoByAccessToken(accessToken: AccessToken): Future[Option[AuthInfo[Account]]] = {
      oauthAccessTokensDAO.findByAccessToken(accessToken.token).flatMap {
        case Some(accessToken) =>
          for {
            account <- accountsDAO.findById(accessToken.accountId)
            client <-  oauthClientsDAO.findById(accessToken.oauthClientId)
          } yield {
            Some(AuthInfo(
              user = account.get,
              clientId = Some(client.get.clientId),
              scope = None,
              redirectUri = None
            ))
          }
        case None => Future.failed(new InvalidRequest())
      }
    }

  }
}
