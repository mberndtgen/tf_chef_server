/* 
 * Chef Server AWS security group 
 * https://docs.chef.io/server_firewalls_and_ports.html
 */

resource "aws_security_group" "chef-server" {
  name        = "${var.hostname}.${var.domain} security group"
  description = "Chef Server ${var.hostname}.${var.domain}"
  vpc_id      = "${var.aws_vpc_id}"
  tags = {
    Name      = "${var.hostname}.${var.domain} security group"
  }
}


# SSH

resource "aws_security_group_rule" "chef-server_allow_22_tcp_allowed_cidrs" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["${split(",", var.allowed_cidrs)}"]
  security_group_id = "${aws_security_group.chef-server.id}"
}


# HTTP (nginx)

resource "aws_security_group_rule" "chef-server_allow_80_tcp" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.chef-server.id}"
}


# HTTPS (nginx)

resource "aws_security_group_rule" "chef-server_allow_443_tcp" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.chef-server.id}"
}


# oc_bifrost (nginx LB)

resource "aws_security_group_rule" "chef-server_allow_9683_tcp" {
  type        = "ingress"
  from_port   = 9683
  to_port     = 9683
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.chef-server.id}"
}


# opscode-push-jobs

resource "aws_security_group_rule" "chef-server_allow_10000-10003_tcp" {
  type        = "ingress"
  from_port   = 10000
  to_port     = 10003
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.chef-server.id}"
}


# Egress: ALL

resource "aws_security_group_rule" "chef-server_allow_egress" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.chef-server.id}"
}
