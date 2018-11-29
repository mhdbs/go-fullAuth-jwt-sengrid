CREATE TABLE `auth`.`authentication` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `organization` VARCHAR(45) NULL,
  `user` VARCHAR(45) NULL,
  `username` VARCHAR(45) NULL,
  `email` VARCHAR(45) NULL,
  `password` VARCHAR(45) NULL,
  PRIMARY KEY (`id`));