# AWS basic settings

provider "aws" {
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  region     = "${var.aws_region}"
}

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


/*
 * Local prep
 * notes: 
 *   - appending a minus sign to the << has the effect that leading tabs are ignored. 
 */

resource "null_resource" "chef-prep" {
  provisioner "local-exec" {
    command = <<-EOT
      rm -rf .chef
      mkdir -p .chef
      openssl rand -base64 512 | tr -d '\r\n' > .chef/encrypted_data_bag_secret
      echo "chef-prep complete"
      EOT
   }
}


# Chef provisiong attributes_json and .chef/dna.json templating

resource "template_file" "attributes-json" {
  template = "${file("${path.module}/files/attributes-json.tpl")}"
  vars {
    addons  = "${join(",", formatlist("\\"%s\\"", split(",", var.server_addons)))}"
    domain  = "${var.domain}"
    host    = "${var.hostname}"
    license = "${var.accept_license}"
    version = "${var.server_version}"
  }
}


# knife.rb templating

resource "template_file" "knife-rb" {
  template = "${file("${path.module}/files/knife-rb.tpl")}"
  vars {
    user   = "${var.username}"
    fqdn   = "${var.hostname}.${var.domain}"
    org    = "${var.org_short}"
  }
}


#
# Provision server
#

resource "aws_instance" "chef-server" {
  depends_on    = ["null_resource.chef-prep"]
  ami           = "${lookup(var.ami_map, "${var.ami_os}-${var.aws_region}")}"
  count         = "${var.server_count}"
  instance_type = "${var.aws_flavor}"
  associate_public_ip_address = "${var.public_ip}"
  subnet_id     = "${var.aws_subnet_id}"
  vpc_security_group_ids = ["${aws_security_group.chef-server.id}"]
  key_name      = "${var.aws_key_name}"
  tags = {
    Name        = "${var.hostname}.${var.domain}"
    Description = "${var.tag_description}"
  }
  root_block_device = {
    # https://www.terraform.io/docs/providers/aws/r/instance.html#block-devices
    delete_on_termination = "${var.root_delete_termination}"
    volume_size = "${var.root_volume_size}"
    volume_type = "${var.root_volume_type}"
  }
  connection {
    host        = "${self.public_ip}"
    user        = "${lookup(var.ami_usermap, var.ami_os)}"
    private_key = "${var.aws_private_key_file}"
  }
  # Setup
  provisioner "local-exec" {
    command = "echo 'Setting up VM; disabling firewall: ${path.module}/files/disable_firewall.sh' >> run.log"
  }
  provisioner "remote-exec" {
    script = "${path.module}/files/disable_firewall.sh"
  }
  provisioner "local-exec" {
    command = "echo 'Installing Chef client' >> run.log"
  }
  provisioner "remote-exec" {
    inline = [
      "mkdir -p .chef",      
      "curl -L https://omnitruck.chef.io/install.sh | sudo bash -s -- -v ${var.client_version}",
      "echo 'Version ${var.client_version} of chef-client installed'"
    ]
  }
  # Execute script to download necessary cookbooks
  provisioner "local-exec" {
    command = "echo 'Executing ${path.module}/files/chef-cookbooks.sh' >> run.log"
  }
  provisioner "remote-exec" {
    script = "${path.module}/files/chef-cookbooks.sh"
  }
  provisioner "local-exec" {
    command = "echo 'Copying ${var.ssl_key} to .chef/${var.hostname}.${var.domain}.key' >> run.log"
  }
  # Put certificate key
  provisioner "file" {
    source      = "${var.ssl_key}"
    destination = ".chef/${var.hostname}.${var.domain}.key"
  }
  provisioner "local-exec" {
    command = "echo 'Copying ${var.ssl_cert} to .chef/${var.hostname}.${var.domain}.pem' >> run.log"
  }
  # Put certificate
  provisioner "file" {
    source      = "${var.ssl_cert}"
    destination = ".chef/${var.hostname}.${var.domain}.pem"
  }
  provisioner "local-exec" {
    command = "echo 'Writing .chef/dna.json, Content: ${template_file.attributes-json.rendered}' >> run.log"
  }
  # Write .chef/dna.json for chef-solo run
  provisioner "remote-exec" {
    inline = [
      "cat > .chef/dna.json <<EOF",
      "${template_file.attributes-json.rendered}",
      "EOF"
    ]
  }
  # Move certs
  provisioner "local-exec" {
    command = "echo 'Moving .chef/${var.hostname}.${var.domain}.* to /var/chef/ssl' >> run.log"
  } 
  provisioner "remote-exec" {
    inline = [
      "sudo mv .chef/${var.hostname}.${var.domain}.* /var/chef/ssl/"
    ]
  }
  # Run chef-solo and get us a Chef server
  provisioner "local-exec" {
    command = "echo 'Running chef-solo' >> run.log"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo chef-solo -j .chef/dna.json -o 'recipe[chef-server::default],recipe[chef-server::addons]'"
    ]
  }
  # Create first user and org
  provisioner "local-exec" {
    command = "echo 'Creating 1st User ${var.username} (Key: .chef/${var.username}.pem) and Org ${var.org_short} (Key: .chef/${var.org_short}-validator.pem)' >> run.log"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo chef-server-ctl user-create ${var.username} ${var.user_firstname} ${var.user_lastname} ${var.user_email} ${base64sha256(self.id)} -f .chef/${var.username}.pem",
      "sudo chef-server-ctl org-create ${var.org_short} '${var.org_long}' --association_user ${var.username} --filename .chef/${var.org_short}-validator.pem"
    ]
  }
  provisioner "local-exec" {
    command = "echo 'Correcting ownership for ${lookup(var.ami_usermap, var.ami_os)} on .chef' >> run.log"
  }
  # Correct ownership on .chef so we can harvest files
  provisioner "remote-exec" {
    inline = [
      "sudo chown -R ${lookup(var.ami_usermap, var.ami_os)} .chef"
    ]
  }
  # Copy back .chef files
  provisioner "local-exec" {
    command = "echo 'Copying (local) ${var.aws_private_key_file} to ${lookup(var.ami_usermap, var.ami_os)}@${aws_instance.chef-server.public_ip}:.chef/* .chef/' >> run.log" /* nothing */
  }
  provisioner "local-exec" {
    command = "scp -r -o stricthostkeychecking=no -i ${var.aws_private_key_file} ${lookup(var.ami_usermap, var.ami_os)}@${aws_instance.chef-server.public_ip}:.chef/* .chef/"
  }
  # Generate knife.rb
  provisioner "local-exec" {
    command = "echo 'Generating (local) knife.rb' >> run.log"
  }
  provisioner "local-exec" {
    command = <<-EOC
      [ -f .chef/knife.rb ] && rm -f .chef/knife.rb
      cat > .chef/knife.rb <<EOF
      ${template_file.knife-rb.rendered}
      EOF
      EOC
  }
  # Upload knife.rb
  provisioner "local-exec" {
    command = "echo 'Uploading knife.rb' >> run.log"
  }
  provisioner "file" {
    source      = ".chef/knife.rb"
    destination = ".chef/knife.rb"
  }
  # Push in cookbooks
  provisioner "local-exec" {
    command = "echo 'Executing cookbooks' >> run.log"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo knife ssl fetch https://chef.itergo.com",
      "sudo mkdir /etc/chef/trusted_certs",
      "sudo cp .chef/trusted_certs/* /etc/chef/trusted_certs/",
    ]
  }
}


# File sourcing redirection

module "encrypted_data_bag_secret" {
  source = "github.com/mengesb/tf_filemodule"
  file   = ".chef/encrypted_data_bag_secret"
}

module "knife_rb" {
  source = "github.com/mengesb/tf_filemodule"
  file   = ".chef/knife.rb"
}

module "user_pem" {
  source = "github.com/mengesb/tf_filemodule"
  file   = ".chef/${var.username}.pem"
}

module "validator" {
  source = "github.com/mengesb/tf_filemodule"
  file   = ".chef/${var.org_short}-validator.pem"
}


# Register Chef server against itself

resource "null_resource" "chef_chef-server" {
  depends_on = ["aws_instance.chef-server"]
  connection {
    host        = "${aws_instance.chef-server.public_ip}"
    user        = "${lookup(var.ami_usermap, var.ami_os)}"
    private_key = "${var.aws_private_key_file}"
  }
/* I guess we don't need that 
  # Provision with Chef
  provisioner "chef" {
    attributes_json = "${template_file.attributes-json.rendered}"
    environment     = "_default"
    log_to_file     = "${var.log_to_file}"
    node_name       = "${aws_instance.chef-server.tags.Name}"
    run_list        = ["recipe[chef-client::default]","recipe[chef-client::config]","recipe[chef-client::cron]","recipe[chef-client::delete_validation]","recipe[chef-server::default]","recipe[chef-server::addons]"]
    server_url      = "https://${aws_instance.chef-server.tags.Name}/organizations/${var.org_short}"
    skip_install    = true
    validation_client_name = "${var.org_short}-validator"
    validation_key  = "${file("${module.validator.file}")}"
    version         = "${var.client_version}"
  }
*/
}


# Generate pretty output format

resource "template_file" "chef-server-creds" {
  depends_on = ["null_resource.chef_chef-server"]
  template = "${file("${path.module}/files/chef-server-creds.tpl")}"
  vars {
    user   = "${var.username}"
    pass   = "${base64sha256(aws_instance.chef-server.id)}"
    user_p = "${module.user_pem.file}"
    fqdn   = "${aws_instance.chef-server.tags.Name}"
    org    = "${var.org_short}"
    pem    = "${module.validator.file}"
  }
}


# Write generated template file

resource "null_resource" "write-files" {
  provisioner "local-exec" {
    command = <<-EOC
      [ -f .chef/chef-server.creds ] && rm -f .chef/chef-server.creds
      cat > .chef/chef-server.creds <<EOF
      ${template_file.chef-server-creds.rendered}
      EOF
      EOC
  }
}
