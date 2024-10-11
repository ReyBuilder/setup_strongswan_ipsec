CA_KEY=
CA_CERT=
HOST_KEY=hostKey.pem
HOST_CERT=hostCert.pem

EXEC=$0
HOST_IP=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}')

help()
{
cat <<EOF
"Usage: $0 [arg=value...]"
"Argument list:"
"   cc|cacert   - certificate authority (CA) pem file"
"   ck|cakey    - certificate authority (CA) key pem file"
EOF
}

RED_FRMT="\e[0;31m"
NO_FRMT="\e[0m"
errecho()
{
    echo -e "${RED_FRMT}$1${NO_FRMT}"
    help
}

install_strongswan()
{
    # update system packages
    sudo apt-get -yq update && sudo apt-get -yq upgrade

    # install sswan
    sudo apt-get -yq install charon-systemd strongswan-swanctl strongswan-pki libstrongswan-extra-plugins libtss2-tcti-tabrmd0
}

generate_host_cert()
{
    # generate host private key
    pki --gen --type rsa --outform pem > /etc/swanctl/private/hostKey.pem

    # generate host certificate
    pki --pub --in /etc/swanctl/private/hostKey.pem --type rsa \
        | pki --issue --lifetime 1825 --cacert /etc/swanctl/x509ca/caCert.pem --cakey /etc/swanctl/private/caKey.pem \
            --dn "O=VelvetVPN, CN=$HOST_IP" \
            --flag serverAuth --flag ikeIntermediate \
            --san "$HOST_IP" --san "$HOST_IP" \
            --outform pem > /etc/swanctl/x509/hostCert.pem
}

copy_ca_cert_and_key()
{
    if [ ! -f "$1" ]; then
        errecho "No CA cert specified"
        exit 1
    fi

    if [ ! -f "$2" ]; then
        errecho "No CA key specified"
        exit 1
    fi

    cp "$1" /etc/swanctl/x509ca/caCert.pem
    cp "$2" /etc/swanctl/private/caKey.pem
}

configure_certs()
{
    copy_ca_cert_and_key $CA_CERT $CA_KEY
    generate_host_cert
}

configure_sswan()
{
    local CONF_FILE="/etc/swanctl/conf.d/mschap.conf"

    rm -f $CONF_FILE

    #write config file
cat > $CONF_FILE <<EOF
connections {
    eap {
        pools = ipv4

        proposals = aes128-sha256-ecp256,aes256-sha384-ecp384,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha384-modp4096,aes256-sha256-modp4096,aes256-sha1-modp4096,aes128-sha256-modp1536,aes128-sha1-modp1536,aes256-sha384-modp2048,aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp1024,aes128-sha1-modp1024,aes256-sha384-modp1536,aes256-sha256-modp1536,aes256-sha1-modp1536,aes256-sha384-modp1024,aes256-sha256-modp1024,aes256-sha1-modp1024

        send_certreq = yes
        send_cert = always

        local {
            auth = pubkey
            certs = hostCert.pem
            id = $HOST_IP
        }

        remote {
            auth = eap-mschapv2
            eap_id = %any
        }

        children {
            eap {
                local_ts = 0.0.0.0/0
                esp_proposals = aes128gcm16-ecp256,aes256gcm16-ecp384,aes128-sha256-ecp256,aes256-sha384-ecp384,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha384-modp4096,aes256-sha256-modp4096,aes256-sha1-modp4096,aes128-sha256-modp1536,aes128-sha1-modp1536,aes256-sha384-modp2048,aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp1024,aes128-sha1-modp1024,aes256-sha384-modp1536,aes256-sha256-modp1536,aes256-sha1-modp1536,aes256-sha384-modp1024,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128gcm16,aes256gcm16,aes128-sha256,aes128-sha1,aes256-sha384,aes256-sha256,aes256-sha1
            }
        }
    }
}

pools {
  ipv4 {
    addrs = 10.3.0.0/24
    dns = 8.8.8.8, 8.8.4.4
  }
}

secrets {
    eap-root {
        id = root
        secret = root
    }
}
EOF
}

restart_strongswan()
{
    systemctl restart strongswan
}

setup_vpn()
{
    install_strongswan
    configure_sswan
    configure_certs
    restart_strongswan
}

if [ "$EUID" -ne 0 ]; then
    errecho "Please run as root"
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        cc=*|cacert=*)
            CA_CERT="${1#*=}"
            shift
            shift
            ;;
        ck=*|cakey=*)
            CA_KEY="${1#*=}"
            shift
            shift
            ;;
        *)
            errecho "Unknown parameter encountered"
            shift
            ;;
    esac
done

setup_vpn