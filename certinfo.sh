#!/bin/bash
#
# certinfo.sh v2.4
# by Ricardo Branco
#
# MIT License
#
# This script parses PEM or DER certificates, requests, CRL's, PKCS#12, PKCS#7 & PKCS#8 files, Java keystores, NSS databases,
#   Diffie-Hellman / DSA / Elliptic Curve parameters and private & public keys (from OpenSSH too).
# To view Java keystores, either Oracle Java or OpenJDK must be installed.
# To view NSS databases we use the certutil command (libnss3-tools on Debian-based systems, nss-tools on RedHat-based).
# In the case of PKCS#12, PKCS#7 files, Java keystores and NSS databases, the 2nd argument must be a password (or a file).
#

# OpenSSL
[[ -z $openssl && ${openssl-set} ]] && \
openssl=${openssl:-$(type -P openssl)}
# Oracle Java / OpenJDK tool
keytool=${keytool:-$(type -P keytool)}
# NSS tools
certutil=${certutil:-$(type -P certutil)}
pk12util=${pk12util:-$(type -P pk12util)}
# OpenSSH
ssh_keygen=${ssh_keygen:-$(type -P ssh-keygen)}

exit_error ()
{
        echo "$@" >&2
        exit 1
}

exit_usage ()
{
	cat <<- EOF
		Usage: ${0##*/} FILE [PASSWORD|PASSWORD_FILE]
		Usage: ${0##*/} -h [https://]SERVER[:PORT]
		Usage: ${0##*/} CRL [CAfile]
	EOF
	exit 1
}

# The openssl x509, req and crl commands just print the first certificate or CRL and doesn't work with concatenated content.
print_openssl ()
{
	tr -d '\r' < "$2" | \
	awk -v command="$openssl $1" '{
		s = s "\n" $0
		if ($0 ~ /^-{5}BEGIN /) {
			s=$0
		}
		else if ($0 ~ /^-{5}END /) {
			print s | command
			close(command)
		}
	}'
}

print_certificate ()
{
	print_openssl "x509 -text -noout" "$1"
}

print_certrequest ()
{
	print_openssl "req -text -noout" "$1"
}

print_crl ()
{
	if [ $# -eq 2 ] ; then
		print_openssl "crl -text -noout -CAfile $2" "$1"
	else
		print_openssl "crl -text -noout" "$1"
	fi
}

print_dhparam ()
{
	$openssl dhparam -text -noout -in "$1"
}

print_dsaparam ()
{
	$openssl dsaparam -text -noout -in "$1"
}

print_ecparam ()
{
	$openssl ecparam -text -noout -in "$1"
}

print_pkcs7 ()
{
	$openssl pkcs7 -text -print_certs -in "$1"
}

print_pkcs8 ()
{
	if [ -f "$2" ] ; then
		$openssl pkcs8 -in "$1" -passin "file:$2"
	else
		$openssl pkcs8 -in "$1" -passin "pass:$2"
	fi
}

print_pkcs12 ()
{
	if [ $# -eq 2 ] ; then
		if [ -f "$2" ] ; then
			$openssl pkcs12 -info -nodes -in "$1" -passin file:"$2"
		else
			$openssl pkcs12 -info -nodes -in "$1" -passin pass:"$2"
		fi
	else
		$openssl pkcs12 -info -nodes -in "$1"
	fi
}

print_nssdb ()
{
	local dir prefix

	[ -z "$certutil" ] && exit_error "Missing command: certutil"

	dir=$(dirname "$1")

	case "$1" in
		*cert[0-9].db)
			prefix=$(basename "$1" | sed 's/cert[0-9].db$//')
			if [ $# -eq 2 ] ; then
				$certutil -L -d "$dir" -P "$prefix" -n "$2"
			else
				$certutil -L -d "$dir" -P "$prefix"
			fi ;;
		*key[0-9].db)
			prefix=$(basename "$1" | sed 's/key[0-9].db$//')
			if [ $# -eq 2 ] ; then
				if [ -f "$2" ] ; then
					$certutil -K -d "$dir" -P "$prefix" -f "$2"
				else
					echo "$2" | $certutil -K -d "$dir" -P "$prefix" -f /dev/stdin
				fi
			else
				$certutil -K -d "$dir" -P "$prefix"
			fi ;;
		*secmod.db)
			$certutil -U -d "$dir" ;;
		*)
			exit 1 ;;
	esac
}

print_publickey ()
{
	local data

	# XXX: There's a bug in the dsa & ec commands returns 1 when -noout is used
	for alg in rsa "rsa -RSAPublicKey_in" dsa ec ; do
		data=$($openssl "$alg" -text -pubin -in "$@" 2>/dev/null | sed -r '/^-{5}BEGIN/,/^-{5}BEGIN/d')
		[ -n "$data" ] && break
	done

	[ -n "$data" ] && echo "$data"
}

print_privatekey ()
{
	local data

	# XXX: There's a bug in the dsa & ec commands returns 1 when -noout is used
	for alg in rsa dsa ec ; do
		if [ $# -eq 2 ] ; then
			if [ -f "$2" ] ; then
				data=$($openssl $alg -text -noout -in "$1" -passin "file:$2" 2>/dev/null)
				[ -n "$data" ] && break
			else
				data=$($openssl $alg -text -noout -in "$1" -passin "pass:$2" 2>/dev/null)
				[ -n "$data" ] && break
			fi
		else
			data=$($openssl $alg -text -noout -in "$1" 2>/dev/null)
			[ -n "$data" ] && break
		fi
	done

	[ -n "$data" ] && echo "$data"
}

print_sshpubkey ()
{
	local tmpfile

	# Create temporary file with secure permissions
	umask 077
	trap 'rm -f $tmpfile' EXIT HUP INT QUIT TERM
	tmpfile=$(mktemp)

	$ssh_keygen -e -m pkcs8 -f "$1" > "$tmpfile"

	print_publickey "$tmpfile"

	rm -f "$tmpfile"
}

print_server ()
{
	local host starttls

	# Strip the initial URL scheme & any trailing slashes, if present
	host=$(echo "$1" | sed -re 's%^[a-z][a-z0-9\.-]+://%%' -e 's%/*$%%')
	# Get port
	[[ $host =~ : ]] && port=${host##*:}
	# Strip port from host
	host=${host%:*}
	# Use port 443 if not specified
	# XXX: Get port from scheme?
	port=${port:-"443"}

	case "$port" in
		21|ftp)
			starttls="ftp" ;;
		25|587|smtp)
			starttls="smtp" ;;
		110|pop3)
			starttls="pop3" ;;
		143|imap)
			starttls="imap" ;;
	esac

	if [ -n "$starttls" ] ; then
		starttls="-starttls $starttls"
	fi

	[[ ! $host =~ ^[0-9] ]] && servername="-servername $host"

	echo QUIT | $openssl s_client -showcerts $starttls "$servername" -connect "${host}:$port" 2>/dev/null | sed -rne '/^-+BEGIN/,/^-+END/p'
}

detect_file ()
{
	local header

	header=$(tr -d '\r\0' < "$1" | grep -E -m1 -e '^-{4,5} ?BEGIN [A-Z0-9 ]+ ?-{4,5}$' -e '^(ssh|ecdsa)-[a-z0-9-]+ [A-Za-z0-9/-]+ ?.*$')

	if [[ $header =~ ^-{5}BEGIN\ [A-Z0-9\ ]+-{5}$ ]] ; then
		# PEM
		type=$(echo "$header" | sed -re 's/^-{5}BEGIN //' -e 's/-{5}$//')
	elif [[ $header =~ ^-{4}\ BEGIN\ [A-Z0-9\ ]+\ -{4}$ ]] ; then
		# RFC-4716 SSH public key format
		type=$(echo "$header" | sed -re 's/^-{4} BEGIN //' -e 's/ -{4}$//')
	elif [[ $header =~ ^(ssh|ecdsa)-[a-z0-9-]+\ [A-Za-z0-9/-]+\ ?.*$ ]] ; then
		# Legacy SSH public key format
		type="SSH2 PUBLIC KEY"
	fi

	[ -z "$type" ] && type=$(file -bL "$1")

	echo "$type"
}

# Support DER format
detect_data ()
{
	local tmpfile command

	# Create temporary file with secure permissions
	umask 077
	trap 'rm -f $tmpfile' EXIT HUP INT QUIT TERM
	tmpfile=$(mktemp)

	for cmd in x509 req crl pkcs7 dhparam dsaparam ecparam rsa ; do
		$openssl $cmd -outform PEM -inform DER -in "$1" > "$tmpfile" 2>/dev/null || continue
		case $cmd in
			x509)
				command="print_certificate" ;;
			req)
				command="print_certrequest" ;;
			crl)
				command="print_crl" ;;
			pkcs7)
				command="print_pkcs7" ;;
			dhparam)
				command="print_dhparam" ;;
			dsaparam)
				command="print_dsaparam" ;;
			ecparam)
				command="print_ecparam" ;;
		esac
		break
	done
	if [ -z "$command" ] ; then
		for alg in rsa dsa ec ; do
			if $openssl $alg -outform PEM -inform DER -pubin -in "$1" > "$tmpfile" 2>/dev/null ; then
				command="print_publickey"
				break
			fi
		done
	fi
	if [ -z "$command" ] ; then
		if [ -f "$2" ] ; then
			$openssl pkcs8 -outform PEM -inform DER -in "$1" -passin "file:$2" > "$tmpfile" 2>/dev/null
		else
			$openssl pkcs8 -outform PEM -inform DER -in "$1" -passin "pass:$2" > "$tmpfile" 2>/dev/null
		fi
		if [ $? -eq 0 ] ; then
                        command="print_privatekey"
                fi
	fi

	if [ -n "$command" ] ; then
		shift
		$command "$tmpfile" "$@"
		exit $?
	else
		print_pkcs12 "$@" && exit
		print_privatekey "$@" && exit
	fi

	rm -f "$tmpfile"
}

# Print Java KeyStore
print_keystore ()
{
	[ -z "$keytool" ] && exit_error "Missing command: keytool"

	if [ $# -eq 2 ] ; then
		if [ -f "$2" ] ; then
			$keytool -list -v -keystore "$1" -storepass:file "$2" || \
			$keytool -list -v -keystore "$1" -storepass "$(< "$2")"
		else
			$keytool -list -v -keystore "$1" -storepass "$2"
		fi
	else
		$keytool -list -v -keystore "$1"
	fi
}

# Translate JKS (Java KeyStore) to PKCS#12 for better viewing
jks2pkcs12 ()
{
	local tmpfile

	[ -z "$keytool" ] && exit_error "Missing command: keytool"

	# Secure permissions
	umask 077
	# Create temp file
	tmpfile=$(mktemp -u)
	trap '/bin/rm -f $tmpfile' EXIT HUP INT QUIT TERM

	if [ -f "$2" ] ; then
		$keytool -importkeystore -noprompt -srckeystore "$1" -srcstoretype JKS -destkeystore "$tmpfile" -deststoretype PKCS12 -srcstorepass:file "$2" -deststorepass file:"$2" || \
		$keytool -importkeystore -noprompt -srckeystore "$1" -srcstoretype JKS -destkeystore "$tmpfile" -deststoretype PKCS12 -srcstorepass "$(< "$2")" -deststorepass "$(< "$2")" || exit 1
	else
		$keytool -importkeystore -noprompt -srckeystore "$1" -srcstoretype JKS -destkeystore "$tmpfile" -deststoretype PKCS12 -srcstorepass "$2" -deststorepass "$2" || exit 1
	fi

	shift
	print_pkcs12 "$tmpfile" "$@"

	rm -f "$tmpfile"
}

if [[ $# -ne 1 && $# -ne 2 ]] ; then
	exit_usage
fi

if [[ $1 = "-h" && $# -eq 2 ]] ; then
	print_server "$2"
	exit
elif [[ $1 =~ ^- ]] ; then
	exit_usage
fi

type=$(detect_file "$1")

case "$type" in
	'PRIVATE KEY' | 'RSA PRIVATE KEY' | 'DSA PRIVATE KEY' | 'EC PRIVATE KEY')
		print_privatekey "$1" ;;
	'ENCRYPTED PRIVATE KEY')
		print_pkcs8 "$@" ;;
	'PUBLIC KEY' | 'RSA PUBLIC KEY')
		print_publickey "$@" ;;
	'SSH2 PUBLIC KEY')
		print_sshpubkey "$1" ;;
	'CERTIFICATE' | 'X509 CERTIFICATE' | 'TRUSTED CERTIFICATE')
		print_certificate "$1" ;;
	'CERTIFICATE REQUEST' | 'NEW CERTIFICATE REQUEST')
		print_certrequest "$1" ;;
	'DH PARAMETERS')
		print_dhparam "$1" ;;
	'DSA PARAMETERS')
		print_dsaparam "$1" ;;
	'EC PARAMETERS')
		print_ecparam "$1" ;;
	'Java KeyStore')
		#print_keystore "$@"
		# Transform the Java Keystore to PKCS#12 for better viewing
		jks2pkcs12 "$@" ;;
	'X509 CRL')
		print_crl "$@" ;;
	'PKCS7')
		print_pkcs7 "$1" ;;
	'Berkeley DB '*)
		print_nssdb "$@" ;;
	'SQLite 3.x database')
		export NSS_DEFAULT_DB_TYPE="sql"
		print_nssdb "$@" ;;
	*)
		detect_data "$@"
		file -L "$1" ;;
esac

