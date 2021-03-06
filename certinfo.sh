#!/bin/bash
#
# certinfo.sh v2.4
# by Ricardo Branco
#
# MIT License
#
# This script parses PEM or DER certificates, requests, CRL's, PKCS#12, PKCS#7 & PKCS#8 files, Java keystores, NSS databases,
#   Diffie-Hellman / DSA / Elliptic Curve parameters and private & public keys (from OpenSSH too).
# It uses OpenSSL for most operations (unless the openssl variable is empty), otherwise it uses GnuTLS' certtool(1),
#   which comes with gnutls-bin package on Debian-based systems and gnutls-utils on RedHat-based.
# Note: If the certtool variable is empty, keytool is used instead.
# To view Java keystores, either Oracle Java or OpenJDK must be installed.
# To view NSS databases we use the certutil command (libnss3-tools on Debian-based systems, nss-tools on RedHat-based).
# In the case of PKCS#12, PKCS#7 files, Java keystores and NSS databases, the 2nd argument must be a password (or a file).
#

# OpenSSL
[[ -z $openssl && ${openssl-set} ]] && \
openssl=${openssl:-$(type -P openssl)}
# GnuTLS
[[ -z $certtool && ${certtool-set} ]] && \
certtool=${certtool:-$(type -P certtool)}
# Oracle Java / OpenJDK tool
keytool=${keytool:-$(type -P keytool)}
# NSS tools
certutil=${certutil:-$(type -P certutil)}
pk12util=${pk12util:-$(type -P pk12util)}
# OpenSSH
ssh_keygen=${ssh_keygen:-$(type -P ssh-keygen)}

exit_usage ()
{
	cat <<- EOF
		Usage: ${0##*/} FILE [PASSWORD|PASSWORD_FILE]
		Usage: ${0##*/} -h [https://]SERVER[:PORT]
		Usage: ${0##*/} CRL [CAfile]
	EOF
	if [ -n "$openssl" ] ; then
		echo "  OpenSSL version: $($openssl version)"
	fi
	if [ -n "$keytool" ] ; then
		echo "  Keytool origin: $($(dirname $keytool)/java -version 2>&1 | sed -ne 2p)"
	fi
	if [ -z "$certtool" -a -z "$openssl" ] ; then
		if [ -f /etc/debian_version ] ; then
			echo "  Install certtool with: apt-get install gnutls-bin"
		elif [ -f /etc/redhat-release ] ; then
			echo "  Install certtool with: yum install gnutls-utils"
		fi
	fi
	if [ -z "$certutil" -o -z "$pk12util" ] ; then
		if [ -f /etc/debian_version ] ; then
			echo "  Install certutil with: apt-get install libnss3-tools"
		elif [ -f /etc/redhat-release ] ; then
			echo "  Install certutil with: yum install nss-tools"
		fi
	fi
	exit 1
}

check_error ()
{
	local binaries

	for bin ; do
		if [[ -x $(eval echo \$$bin) ]] ; then
			binaries="$binaries $bin"
		fi
	done

	echo "ERROR: Missing binaries: $binaries" >&2
	exit_usage
}

# The openssl x509, req and crl commands just print the first certificate or CRL and doesn't work with concatenated content.
print_openssl ()
{
	cat "$2" | tr -d '\r' | \
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
	if [ -n "$openssl" ] ; then
		print_openssl "x509 -text -noout" "$1"
	elif [ -n "$certtool" ] ; then
		$certtool --certificate-info --infile "$1"
	elif [ -n "$keytool" ] ; then
		$keytool -printcert -v -file "$1"
	else
		check_error openssl certtool keytool
	fi
}

print_certrequest ()
{
	if [ -n "$openssl" ] ; then
		print_openssl "req -text -noout" "$1"
	elif [ -n "$certtool" ] ; then
		$certtool --crq-info --infile "$1"
	elif [ -n "$keytool" ] ; then
		$keytool -printcertreq -v -file "$1"
	else
		check_error openssl certtool keytool
	fi
}

print_crl ()
{
	if [ -n "$openssl" ] ; then
		if [ $# -eq 2 ] ; then
			print_openssl "crl -text -noout -CAfile $2" "$1"
		else
			print_openssl "crl -text -noout" "$1"
		fi
	elif [ -n "$certtool" ] ; then
		if [ $# -eq 2 ] ; then
			$certtool --crl-info --infile "$1" --verify-crl --load-ca-certificate "$2"
		else
			$certtool --crl-info --infile "$1"
		fi
	elif [ -n "$keytool" ] ; then
		$keytool -printcrl -v -file "$1"
	else
		check_error openssl certtool keytool
	fi
}

print_dhparam ()
{
	[ -z "$openssl" ] && \
		check_error openssl

	$openssl dhparam -text -noout -in "$1"
}

print_dsaparam ()
{
	[ -z "$openssl" ] && \
		check_error openssl

	$openssl dsaparam -text -noout -in "$1"
}

print_ecparam ()
{
	[ -z "$openssl" ] && \
		check_error openssl

	$openssl ecparam -text -noout -in "$1"
}

print_pkcs7 ()
{
	[ -z "$openssl" ] && \
		check_error openssl

	$openssl pkcs7 -text -print_certs -in "$1"
}

print_pkcs8 ()
{
	[ -z "$openssl" ] && \
		check_error openssl

	if [ -f "$2" ] ; then
		$openssl pkcs8 -in "$1" -passin "file:$2"
	else
		$openssl pkcs8 -in "$1" -passin "pass:$2"
	fi
}

print_pkcs12 ()
{
	if [ -n "$openssl" ] ; then
		if [ $# -eq 2 ] ; then
			if [ -f "$2" ] ; then
				$openssl pkcs12 -info -nodes -in "$1" -passin file:"$2"
			else
				$openssl pkcs12 -info -nodes -in "$1" -passin pass:"$2"
			fi
		else
			$openssl pkcs12 -info -nodes -in "$1"
		fi
	elif [ -n "$certtool" ] ; then
		if [ $# -eq 2 ] ; then
			$certtool --inraw --p12-info --infile "$1" --password "$2"
		else
			$certtool --inraw --p12-info --infile "$1"
		fi
	elif [ -n "$pk12util" ] ; then
		if [ $# -eq 2 ] ; then
			if [ -f "$2" ] ; then
				$pk12util -l "$1" -w "$2"
			else
				$pk12util -l "$1" -W "$2"
			fi
		else
			$pk12util -l "$1"
		fi
	elif [ -n "$keytool" ] ; then
		if [ $# -eq 2 ] ; then
			if [ -f "$2" ] ; then
				$keytool -list -v -storetype PKCS12 -keystore "$1" -storepass:file "$2" || \
				$keytool -list -v -storetype PKCS12 -keystore "$1" -storepass $(< "$2")
			else
				$keytool -list -v -storetype PKCS12 -keystore "$1" -storepass "$2"
			fi
		else
			$keytool -list -v -storetype PKCS12 -keystore "$1"
		fi
	else
		check_error openssl certtool pk12util keytool
	fi
}

print_nssdb ()
{
	local dir prefix

	[ -z "$certutil" ] && \
		check_error certutil

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

	[ -z "$openssl" ] && \
		check_error openssl

	# XXX: There's a bug in the dsa & ec commands returns 1 when -noout is used
	for alg in rsa "rsa -RSAPublicKey_in" dsa ec ; do
		data=$($openssl $alg -text -pubin -in "$@" 2>/dev/null | sed -r '/^-{5}BEGIN/,/^-{5}BEGIN/d')
		[ -n "$data" ] && break
	done

	[ -n "$data" ] && echo "$data"
}

print_privatekey ()
{
	local data

	[ -z "$openssl" ] && \
		check_error openssl

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
	trap "rm -f $tmpfile" EXIT HUP INT QUIT TERM
	tmpfile=$(mktemp)

	$ssh_keygen -e -m pkcs8 -f "$1" > $tmpfile

	print_publickey $tmpfile

	rm -f $tmpfile
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
		21|smtp)
			starttls="ftp" ;;
		25|587|smtp)
			starttls="smtp" ;;
		110|pop3)
			starttls="pop3" ;;
		143|imap)
			starttls="imap" ;;
	esac

	if [ -n "$starttls" ] ; then
		if [ -n "$openssl" ] ; then
			starttls="-starttls $starttls"
		elif [ -n "$certtool" ] ; then
			# XXX: GnuTLS --starttls option sucks
			starttls="--starttls $starttls"
		fi
	fi

	[[ ! $host =~ ^[0-9] ]] && servername="-servername $host"

	if [ -n "$openssl" ] ; then
		echo QUIT | $openssl s_client -showcerts $starttls $servername -connect "${host}:$port" 2>/dev/null
	elif [ -n "$certtool" ] ; then
		echo QUIT | $(dirname $certtool)/gnutls-cli --insecure --print-cert "$host" -p "$port"
	else
		check_error openssl gnutls-cli
	fi | sed -rne '/^-+BEGIN/,/^-+END/p'
}

detect_file ()
{
	local header

	header=$(cat "$1" | tr -d '\r\0' | grep -E -m1 -e '^-{4,5} ?BEGIN [A-Z0-9 ]+ ?-{4,5}$' -e '^(ssh|ecdsa)-[a-z0-9-]+ [A-Za-z0-9/-]+ ?.*$')

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
	trap "rm -f $tmpfile" EXIT HUP INT QUIT TERM
	tmpfile=$(mktemp)

	if [ -n "$openssl" ] ; then
		for cmd in x509 req crl pkcs7 dhparam dsaparam ecparam rsa ; do
			$openssl $cmd -outform PEM -inform DER -in "$1" > $tmpfile 2>/dev/null || continue
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
				if $openssl $alg -outform PEM -inform DER -pubin -in "$1" > $tmpfile 2>/dev/null ; then
					command="print_publickey"
					break
				fi
			done
		fi
		if [ -z "$command" ] ; then
			if [ -f "$2" ] ; then
				$openssl pkcs8 -outform PEM -inform DER -in "$1" -passin "file:$2" > $tmpfile 2>/dev/null
			else
				$openssl pkcs8 -outform PEM -inform DER -in "$1" -passin "pass:$2" > $tmpfile 2>/dev/null
			fi
			[ $? -eq 0 ] && command="print_privatekey"
		fi
	elif [ -n "$certtool" ] ; then
		for cmd in certificate-info crq-info crl-info ; do
			$certtool --$cmd --inraw --infile "$1" > $tmpfile 2>/dev/null || continue
			case $cmd in
				certificate-info)
					command="print_certificate" ;;
				crq-info)
					command="print_certrequest" ;;
				crl-info)
					command="print_crl" ;;
			esac
			break
		done
	else
		check_error openssl certtool
	fi

	if [ -n "$command" ] ; then
		shift
		$command $tmpfile "$@"
		exit $?
	else
		print_pkcs12 "$@" && exit
		print_privatekey "$@" && exit
	fi

	rm -f $tmpfile
}

# Print Java KeyStore
print_keystore ()
{
	[ -z "$keytool" ] && \
		check_error keytool

	if [ $# -eq 2 ] ; then
		if [ -f "$2" ] ; then
			$keytool -list -v -keystore "$1" -storepass:file "$2" || \
			$keytool -list -v -keystore "$1" -storepass $(< "$2")
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

	[ -z "$keytool" ] && \
		check_error keytool

	# Secure permissions
	umask 077
	# Create temp file
	tmpfile=$(mktemp -u)
	trap "/bin/rm -f $tmpfile" EXIT HUP INT QUIT TERM

	if [ -f "$2" ] ; then
		$keytool -importkeystore -noprompt -srckeystore "$1" -srcstoretype JKS -destkeystore "$tmpfile" -deststoretype PKCS12 -srcstorepass:file "$2" -deststorepass file:"$2" || \
		$keytool -importkeystore -noprompt -srckeystore "$1" -srcstoretype JKS -destkeystore "$tmpfile" -deststoretype PKCS12 -srcstorepass $(< "$2") -deststorepass $(< "$2") || exit 1
	else
		$keytool -importkeystore -noprompt -srckeystore "$1" -srcstoretype JKS -destkeystore "$tmpfile" -deststoretype PKCS12 -srcstorepass "$2" -deststorepass "$2" || exit 1
	fi

	shift
	print_pkcs12 "$tmpfile" "$@"

	rm -f "$tmpfile"
}

if [ $# -ne 1 -a $# -ne 2 ] ; then
	exit_usage
fi

if [ "$1" == "-h" -a $# -eq 2 ] ; then
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

