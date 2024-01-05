data_dir           = "/opt/nomad"                                                                                                                                                                                   
enable_syslog      = true
region             = "${os_region}"
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
  bootstrap_expect = ${bootstrap_expect}
  server_join {
    retry_join     = [ "provider=os tag_key=nomad-role tag_value=server auth_url=${auth_url} user_name=${user_name} domain_name=${os_domain_name} password=\"${password}\" region=${os_region}" ] 
    retry_interval = "15s"
  }
}

client {
  enabled = false
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
}

telemetry {
  collection_interval = "1s"
  disable_hostname = true
  prometheus_metrics = true
  publish_allocation_metrics = true
  publish_node_metrics = true
}

# "${floatingip}"
