variable "db_password" {
  type        = string
  sensitive   = true
  description = "Database master password"
}

resource "aws_db_instance" "production_db" {
  allocated_storage    = 20
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  name                 = "production"
  username             = "dbadmin"
  password             = var.db_password
  parameter_group_name = "default.postgres14"
  skip_final_snapshot  = true
}
