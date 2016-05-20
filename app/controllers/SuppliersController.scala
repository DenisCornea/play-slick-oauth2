package controllers

import javax.inject._

import models.daos.{AbstractBaseDAO, BaseDAO, SuppliersDAO}
import models.entities.Supplier
import models.persistence.SlickTables.SuppliersTable
import play.api.libs.json.{Json, Writes}
import play.api.mvc._

import scala.concurrent.{ExecutionContext, Future}

@Singleton
class SuppliersController @Inject()(suppliersDAO : SuppliersDAO)(implicit exec: ExecutionContext) extends Controller {

  implicit val supplierWrites = new Writes[Supplier] {
    def writes(sup: Supplier) = Json.obj(
      "id" -> sup.id,
      "name" -> sup.name,
      "desc" -> sup.desc
    )
  }

  def supplier(id : Long) = Action.async {
    suppliersDAO.findById(id) map { sup => sup.fold(NoContent)(sup => Ok(Json.toJson(sup))) }
  }

  def insertSupplier = Action.async(parse.json) {
    request =>
      {
        for {
          name <- (request.body \ "name").asOpt[String]
          desc <- (request.body \ "desc").asOpt[String]
        } yield {
          (suppliersDAO.insert(Supplier(0, name, desc)) map { n => Created("Id of Supplier Added : " + n) }).recoverWith {
            case e => Future {
              InternalServerError("There was an error at the server")
            }
          }
        }
      }.getOrElse(Future{BadRequest("Wrong json format")})
  }
}
