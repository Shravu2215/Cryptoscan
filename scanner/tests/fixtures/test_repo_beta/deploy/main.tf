resource "aws_db_instance" "prod_db" {
  allocated_storage    = 20
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  username             = "dbadmin"
  database_secret      = "super_secret_production_key_12345"
  environment_tag      = var.environment
}
