data_dir           = "/opt/nomad"                                                                                                                                                                                   
enable_syslog      = true
region             = "${ps_region}"
datacenter         = "${datacenter_name}"

advertise {
  # Defaults to the first private IP address.
  http = "{{ GetInterfaceIP \"ens3\" }}" # must be reachable by Nomad CLI clients
  rpc  = "{{ GetInterfaceIP \"ens3\" }}" # must be reachable by Nomad client nodes
  serf = "${floatingip}"                 # must be reachable by Nomad server nodes
}

ports {
  http = 4646
  rpc  = 4647
  serf = 4648
}

server {
  enabled          = true
  encrypt          = "${nomad_encryption_key}"
# authoritative_region = "${auth_region}"  
  bootstrap_expect = ${bootstrap_expect}
  server_join {
    retry_join     = [ "provider=os tag_key=nomad-role tag_value=server auth_url=${auth_url} user_name=${user_name} domain_name=${os_domain_name} password=\"${password}\" region=${os_region}" ] 
    retry_interval = "15s"
  }
}

client {
  enabled = false
}

consul {
  grpc_ca_file = "/etc/consul/certificates/ca.pem"
  grpc_address = "127.0.0.1:8503"
  ca_file      = "/etc/consul/certificates/ca.pem"
  cert_file    = "/etc/consul/certificates/cert.pem"
  key_file     = "/etc/consul/certificates/private_key.pem"
  ssl          = true
  address      = "127.0.0.1:8501"
  auto_advertise = true
  server_service_name = "${node_name}"
  token        = "${token}"
}

tls {
  http = true
  rpc  = true
  ca_file   = "/etc/nomad/certificates/ca.pem"
  cert_file = "/etc/nomad/certificates/cert.pem"
  key_file  = "/etc/nomad/certificates/private_key.pem"

  verify_server_hostname = false
  verify_https_client    = false
}

# Enable and configure ACLs
acl {
  enabled    = true
  token_ttl  = "500s"
  policy_ttl = "500s"
  role_ttl   = "500s"
# replication_token = ""
}

telemetry {
  collection_interval = "1s"
  disable_hostname = true
  prometheus_metrics = true
  publish_allocation_metrics = true
  publish_node_metrics = true
}

# "${floatingip}"
