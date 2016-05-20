import com.google.inject.name.Names
import com.google.inject.{AbstractModule, Provides}
import java.time.Clock

import models.daos._
import models.entities.Supplier
import models.persistence.SlickTables
import models.persistence.SlickTables.SuppliersTable


/**
 * This class is a Guice module that tells Guice how to bind several
 * different types. This Guice module is created when the Play
 * application starts.

 * Play will automatically use any class called `Module` that is in
 * the root package. You can create modules in other locations by
 * adding `play.modules.enabled` settings to the `application.conf`
 * configuration file.
 */
class Module extends AbstractModule {

  override def configure() = {
    // Use the system clock as the default implementation of Clock
    bind(classOf[Clock]).toInstance(Clock.systemDefaultZone)
    bind(classOf[SuppliersDAO]).to(classOf[SuppliersDAOImpl])
    bind(classOf[AccountsDAO]).to(classOf[AccountsDAOImpl])
    bind(classOf[OauthAuthorizationCodesDAO]).to(classOf[OauthAuthorizationCodesDAOImpl])
    bind(classOf[OauthAccessTokensDAO]).to(classOf[OauthAccessTokensDAOImpl])
    bind(classOf[OauthClientsDAO]).to(classOf[OauthClientsDAOImpl])
  }

}



