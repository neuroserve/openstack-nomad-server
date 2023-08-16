locals {
    nomad_version="1.6.0"
    consul_version="1.16.0"
    envoy_version="1.25.6"
}

variable "auth_url" {
  type    = string
  default = "https://myauthurl5000" 
}

variable "user_name" {
  type    = string
  default = "username" 
}

variable "password" {
  type    = string
  default = "totalgeheim" 
}

variable "tenant_name" {
  type    = string
  default = "myproject"
}

variable "user_domain_name" {
  type    = string
  default = "mydomain"
}

variable "region" {
  type   = string
  default = "myregion"
}


#
# This assumes, that you already have a CA - see "nomad tls ca -help" if you don't have one yet
#

resource "tls_private_key" "nomad" {
    count = var.config.server_replicas
    algorithm = "RSA"
    rsa_bits  = "4096"
}

resource "tls_cert_request" "nomad" {
    count = "${var.config.server_replicas}"
#   key_algorithm   = "${element(tls_private_key.nomad.*.algorithm, count.index)}"
    private_key_pem = "${element(tls_private_key.nomad.*.private_key_pem, count.index)}"

    dns_names = [
        "nomad",
        "nomad.local",
        "server.${var.config.datacenter_name}.nomad",
        "nomad.service.${var.config.domain_name}",
    ]

    subject {
        common_name = "server.${var.config.datacenter_name}.nomad"
        organization = var.config.organization.name
    }
}

resource "tls_locally_signed_cert" "nomad" {
    count = var.config.server_replicas
    cert_request_pem = "${element(tls_cert_request.nomad.*.cert_request_pem, count.index)}"
#   ca_key_algorithm = "{(element(tls_cert_request.nomad.*.key_algorithm)}"

    ca_private_key_pem = file("${var.config.private_key_pem}")
    ca_cert_pem        = file("${var.config.certificate_pem}")

    validity_period_hours = 8760

    allowed_uses = [
        "cert_signing",
        "client_auth",
        "digital_signature",
        "key_encipherment",
        "server_auth",
    ]
}

resource "tls_private_key" "consul" {
    count = var.config.server_replicas
    algorithm = "RSA"
    rsa_bits  = "4096"
}

# Create the request to sign the cert with our CA
resource "tls_cert_request" "consul" {
    count = "${var.config.server_replicas}"
    private_key_pem = "${element(tls_private_key.consul.*.private_key_pem, count.index)}"

    dns_names = [
        "consul",
        "consul.local",
    ]

    subject {
        common_name  = "consul.local"
        organization = var.config.organization.name
    }
}

resource "tls_locally_signed_cert" "consul" {
    count = var.config.server_replicas
    cert_request_pem = "${element(tls_cert_request.consul.*.cert_request_pem, count.index)}"

    ca_private_key_pem = file("${var.config.private_key_pem}")
    ca_cert_pem        = file("${var.config.certificate_pem}")

    validity_period_hours = 8760

    allowed_uses = [
        "cert_signing",
        "client_auth",
        "digital_signature",
        "key_encipherment",
        "server_auth",
    ]
}

resource "random_id" "nomad_encryption_key" {
    byte_length = 32
}

data "openstack_images_image_v2" "os" {
  name        = "debian-11-consul"
  most_recent = "true"
}

resource "openstack_compute_keypair_v2" "user_keypair" {
  name       = "tf_nomad"
  public_key = file("${var.config.keypair}")
}

resource "openstack_networking_secgroup_v2" "sg_nomad" {
  name        = "sg_nomad"
  description = "Security Group for servergroup"
}

resource "openstack_networking_secgroup_rule_v2" "sr_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_dns1" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_dns2" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8300tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8300
  port_range_max    = 8300
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8300udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 8300
  port_range_max    = 8300
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8301tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8301
  port_range_max    = 8301
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8301udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 8301
  port_range_max    = 8301
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8302tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8302
  port_range_max    = 8302
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8302udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 8302
  port_range_max    = 8302
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8600tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8600
  port_range_max    = 8600
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8600udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 8600
  port_range_max    = 8600
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8500tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8500
  port_range_max    = 8500
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_8501tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8501
  port_range_max    = 8501
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_4646tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 4646
  port_range_max    = 4646
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_4647tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 4647
  port_range_max    = 4647
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_4648tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 4648
  port_range_max    = 4648
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}

resource "openstack_networking_secgroup_rule_v2" "sr_4648udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 4648
  port_range_max    = 4648
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sg_nomad.id
}


resource "openstack_networking_floatingip_v2" "nomad_flip" {
  count = var.config.server_replicas
  pool  = "ext01"
}

resource "openstack_compute_floatingip_associate_v2" "nomad_flip" {
   count       = var.config.server_replicas
   floating_ip = "${element(openstack_networking_floatingip_v2.nomad_flip.*.address, count.index)}"
   instance_id = "${element(openstack_compute_instance_v2.nomad.*.id, count.index)}"
}

resource "openstack_compute_instance_v2" "nomad" {
  name            = "nomad-${count.index}"
  image_id        = data.openstack_images_image_v2.os.id
  flavor_name     = var.config.flavor_name
  key_pair        = openstack_compute_keypair_v2.user_keypair.name
  count           = var.config.server_replicas
  security_groups = ["sg_nomad", "default"]   
  scheduler_hints {
    group = openstack_compute_servergroup_v2.nomadcluster.id
  }

#  network {
#    uuid = var.config.instance_backnet_uuid
#  }

  network {
    uuid = var.config.instance_network_uuid
  }
  
  metadata = {
     nomad-role = "server"
     consul-role = "client"
  }

  connection {
       type = "ssh"
       user = "root" 
       private_key = file("${var.config.connkey}")
       agent = "true" 
       bastion_host = "${var.config.bastionhost}"
       bastion_user = "debian" 
       bastion_private_key = file("${var.config.connkey}")
       host = self.access_ip_v4
  }

  provisioner "remote-exec" {
        inline = [
            "sudo apt-get update",
            "sudo mkdir -p /etc/nomad/certificates",
            "sudo mkdir -p /opt/nomad",
            "sudo useradd --system --home /etc/nomad --shell /bin/false nomad",
            "sudo chown nomad /opt/nomad",
            "sudo chgrp nomad /opt/nomad",
        ]
   }

  provisioner "remote-exec" {
        inline = [
            "sudo apt-get update",
            "sudo mkdir -p /etc/consul/certificates",
            "sudo mkdir -p /opt/consul",
            "sudo useradd -d /opt/consul consul",
            "sudo chown consul /opt/consul",
            "sudo chgrp consul /opt/consul",
        ]
   }

   provisioner "file" {
        content = file("${var.config.certificate_pem}")
        destination = "/etc/nomad/certificates/ca.pem"
   }

   provisioner "file" {
        content = tls_locally_signed_cert.nomad[count.index].cert_pem
        destination = "/etc/nomad/certificates/cert.pem"
   }

   provisioner "file" {
        content = tls_private_key.nomad[count.index].private_key_pem
        destination = "/etc/nomad/certificates/private_key.pem"
   }

   provisioner "file" {
        content = templatefile("${path.module}/templates/nomad.service.tpl", {
            floatingip = "${element(openstack_networking_floatingip_v2.nomad_flip.*.address, count.index)}",
        })
        destination = "/etc/systemd/system/nomad.service" 
   }

   provisioner "remote-exec" {
      inline = [
        "chown consul /etc/consul/certificates",
        "chgrp consul /etc/consul/certificates",
      ]
   }

   provisioner "file" {
      content = file("${var.config.certificate_pem}")
      destination = "/etc/consul/certificates/ca.pem"
   }

   provisioner "file" {
      content = tls_locally_signed_cert.consul[count.index].cert_pem
      destination = "/etc/consul/certificates/cert.pem"
   }

   provisioner "file" {
      content = tls_private_key.consul[count.index].private_key_pem
      destination = "/etc/consul/certificates/private_key.pem"
   }

   provisioner "file" {
    source = "${path.root}/files/consul.service"
    destination = "/etc/systemd/system/consul.service" 
   }

   provisioner "file" {
        content = templatefile("${path.module}/templates/nomad.hcl.tpl", {
            datacenter_name = var.config.datacenter_name,
            domain_name = var.config.domain_name,
            os_domain_name = var.config.os_domain_name,
            node_name = "nomad-${count.index}",
            bootstrap_expect = var.config.server_replicas,
            nomad_encryption_key = random_id.nomad_encryption_key.b64_std,
            upstream_dns_servers = var.config.dns_servers,
            auth_url = "${var.auth_url}",
            user_name = "${var.user_name}",
            password = "${var.password}",
            os_region   = "${var.config.os_region}",
        })
        destination = "/etc/nomad/nomad.hcl"
   }

  provisioner "file" {
     content = templatefile("${path.module}/templates/consul.hcl.tpl", {
        datacenter_name = var.config.consul_datacenter_name,
        node_name = "nomad-${count.index}"
        encryption_key = var.config.consul_encryption_key,
        os_domain_name = var.config.os_domain_name,
        auth_url = "${var.auth_url}",
        user_name = "${var.user_name}",
        password = "${var.password}",
        os_region   = "${var.config.os_region}",
     })
     destination = "/etc/consul/consul.hcl"
  }


  provisioner "remote-exec" {
        inline = [
            "curl -L https://func-e.io/install.sh | bash -s -- -b /usr/local/bin",
            "export ENVOY_VERSION_STRING=${local.envoy_version} ; func-e use $ENVOY_VERSION_STRING",
            "cp /root/.func-e/versions/${local.envoy_version}/bin/envoy /usr/local/bin",
        ]
   }

   provisioner "remote-exec" {
        inline = [
            "cd /tmp ; wget --no-check-certificate https://releases.hashicorp.com/consul/${local.consul_version}/consul_${local.consul_version}_linux_amd64.zip",
            "cd /tmp ; unzip consul_${local.consul_version}_linux_amd64.zip",
            "cd /tmp ; rm consul_${local.consul_version}_linux_amd64.zip",

            "mv /tmp/consul /usr/local/bin/consul",
            "sudo systemctl enable consul",
            "sudo systemctl start consul",
        ]
   }

   provisioner "remote-exec" {
        inline = [
            "cd /tmp ; wget --no-check-certificate https://releases.hashicorp.com/nomad/${local.nomad_version}/nomad_${local.nomad_version}_linux_amd64.zip",
            "cd /tmp ; unzip nomad_${local.nomad_version}_linux_amd64.zip",
            "cd /tmp ; rm nomad_${local.nomad_version}_linux_amd64.zip",

            "mv /tmp/nomad /usr/local/bin/nomad",
            "sudo systemctl enable nomad",
            "sudo systemctl start nomad",
        ]
   }
}

resource "openstack_compute_servergroup_v2" "nomadcluster" {
  name = "aaf-sg"
  policies = ["anti-affinity"]
}

output "nomad_encryption_key" {
    sensitive = true
    value = random_id.nomad_encryption_key.b64_std
}

