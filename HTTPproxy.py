
"""
    Name: Emile Goulard
    uID: u1244855
    Date: 3/11/2023

    Class: CS4480 - Computer Networks
    Assignment: PA1-Final

    Summary:
        This Python file acts as an HTTP Proxy to filter Client Requests to the Target Server.

        The client sends all its requests to the proxy. Upon receiving a client’s request, 
        the proxy opens a connection to the server and passes on the request. The proxy receives 
        the reply from the server and then sends that reply back to the client.
"""

''' Imports '''
import signal
from socket import *
import sys
from time import *
from urllib.parse import urlparse
from optparse import OptionParser
from urllib.parse import urlparse
from threading import *

'''Global Variables to Manage Cache and Blocklists'''
cacheList = dict()
blockList = []
cacheEnabled = False
blockListEnabled = False

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
	sys.exit(0)

# Called from 'Handle_Client_Request' to receive HTTP response from target server
def Filter_Server_Response(client_conn, uri_hostname, uri_port, uri_path, http_method, http_version, total_headers):
    """
    Retrieves the target server response to send back to Client.
    
    Responses can be directly from the target server or from the cache (if enabled).

    Parameters
    ----------
    client_conn : The client connection (socket)

    uri_hostname : The host name portion of the client URL request - (string)

    uri_port : The port number of the client URL request - (string)

    uri_path : The path portion of the client URL request - (string)

    http_method : The HTTP method (only 'GET' is accepted) - (string)

    http_version : The HTTP version used (only HTTP/1.0 allowed) - (string)

    total_headers : total_headers : The total optional headers obtained from Client input - (list)
    """

    # Set Connection to Host URL
    webserver_skt = socket(AF_INET, SOCK_STREAM)
    webserver_skt.connect((uri_hostname, uri_port))
    server_response = f'{http_method} {uri_path} {http_version}\r\n'
    server_response += f'Host: {uri_hostname}\r\n'

    # If proxy’s cache is enabled and a client requests object Obj
    if cacheEnabled and Check_In_Cache(uri_hostname, uri_port, uri_path):
        Obtain_Request_From_Cache(client_conn, webserver_skt, server_response, uri_hostname, uri_port, uri_path)
    else:
        Obtain_Request_From_Server(client_conn, webserver_skt, server_response, total_headers)

# This method is called when the cache is enabled and Object is in cache
def Obtain_Request_From_Cache(client_conn, webserver_skt, server_response, uri_hostname, uri_port, uri_path):
    """
    Grabs the stored response from our Proxy's cache.

    Checks if the response in our cache has been modified.
    If it is, we must update the proxy with the new response into our cache. 
    Otherwise, send back same response from cache.
    
    Once the response is obtained, close the connection with the Client and Proxy to target server.
    If at any point the response times out, send out '404 Not Found' response.

    Parameters
    ----------
    client_conn : The client connection (socket)

    webserver_skt : The proxy connection to server (socket)

    server_response : The response the server will send to Client (string)

    uri_hostname : The host name portion of the client URL request (string)

    uri_port : The port number of the client URL request (string)

    uri_path : The path portion of the client URL request (string)
    """

    DATE = ''
    OBJ = (uri_hostname, uri_port, uri_path)
    response_lines = cacheList[OBJ].splitlines()
    for line in response_lines:
        # Conditional GET to check last modified
        if b'Last-Modified' in line:
            last_modified_line = line.split(':')
            DATE = last_modified_line[-1]
            server_response += f'If-Modified-Since: {DATE}\r\nConnection: close\r\n\r\n'
            webserver_skt.sendall(server_response.encode())

            # Gather the data sent from server
            try:
                total_data = b''
                while not total_data.endswith(b'\r\n\r\n'):
                    data = webserver_skt.recv(4096)
                    if not data:
                        break
                    total_data += data
            except Exception:
                Invalid_HTTP_Request(404, client_conn)

            # Now parse the total data sent and look to see if the OBJ has been modified since last request
            total_data_parse = total_data.decode().splitlines()
            for line in total_data_parse:
                # Proxy already has up-to-date copy of OBJ
                if 'HTTP/1.1 304 Not Modified' in line:
                    client_conn.sendall(cacheList[OBJ])
                    client_conn.close()
                    webserver_skt.close()
                    return
                
            # Updated version of OBJ, therefore send that out and update the cache
            Add_To_Cache(uri_hostname, uri_port, uri_path, total_data)
            client_conn.sendall(total_data)
            client_conn.close()
            webserver_skt.close()
            return

# This method is called when the cache is disabled    
def Obtain_Request_From_Server(client_conn, webserver_skt, server_response, total_headers):
    """
    Grabs the response from the target server with our Proxy. 

    Once the response is obtained, close the connection with the Client and Proxy to target server.
    If at any point the response times out, send out '404 Not Found' response.

    Parameters
    ----------
    client_conn : The client connection (socket)

    webserver_skt : The proxy connection to server (socket)

    server_response : The response the server will send to Client (string)

    total_headers : The total optional headers obtained from Client input (list)
    """

    # Place in any additional headers prior to connection close
    for additional_header in total_headers:
        server_response += f'{additional_header}\r\n'
    server_response += 'Connection: close\r\n\r\n'

    # Send HTTP Formatting
    webserver_skt.sendall(server_response.encode())

    # Handle Response from Webserver
    try:
        total_data = b''
        while not total_data.endswith(b'\r\n\r\n'):
            data = webserver_skt.recv(4096)
            if not data:
                break
            total_data += data
    except Exception:
        Invalid_HTTP_Request(404, client_conn)

    # Send HTTP Response back and make sure to close WebServer and Client Connection  
    client_conn.sendall(total_data)
    client_conn.close()
    webserver_skt.close()
    return

def Invalid_HTTP_Request(error_code, client_conn):
    """
    This method Handles Invalid HTTP Requests from the Client's input.
    
    When the Client makes an invalid request, the Proxy will send the error response back
    and then send that encoded data back to the Client. Lastly, it will close the connection
    with the Client.

    Parameters
    ----------
    error_code : The HTTP response status code to report back to client (int)

    client_conn : The client connection (socket)
    """

    if error_code == 501:
        error_server_response = 'HTTP/1.0 501 Not Implemented\r\n\r\nConnection: close\r\n\r\n'
    elif error_code == 400:
        error_server_response = 'HTTP/1.0 400 Bad Request\r\n\r\nConnection: close\r\n\r\n'
    elif error_code == 403:
        error_server_response = 'HTTP/1.0 403 Forbidden\r\n\r\nConnection: close\r\n\r\n'
    elif error_code == 404:
        error_server_response = 'HTTP/1.0 404 Not Found\r\n\r\nConnection: close\r\n\r\n'

    # Send error response back to client, close connection, and stop program
    client_conn.sendall(error_server_response.encode())
    client_conn.close()
    sys.exit()

# This function is necessary for hashing the values before adding to the dictionary of cache
def Add_To_Cache(uri_hostname: str, uri_port: str, uri_path: str, data: bytes):
    """
    This method adds the data (filtered through the server) to the cache.
    The cache does not accept duplicate entries.

    Parameters
    ----------
    uri_hostname : The host name portion of the client URL request (string)

    uri_port : The port number of the client URL request (string)

    uri_path : The path portion of the client URL request (string)

    data : The server's response data to add in the cache (bytes)
    """

    OBJ = (uri_hostname, uri_port, uri_path)
    cacheList[OBJ] = data

# Checks if the entry is in the cache
def Check_In_Cache(uri_hostname: str, uri_port: str, uri_path: str):
    """
    This method looks if the entry, specified in the input parameters, 
    is inside the cache. If the cache is disabled, then Object is not in the cache.

    Parameters
    ----------
    uri_hostname : The host name portion of the client URL request (string)

    uri_port : The port number of the client URL request (string)

    uri_path : The path portion of the client URL request (string)

    Returns
    -------
    True/False : The Object is in the cachelist
    """

    if not cacheEnabled:
        return False
    
    OBJ = (uri_hostname, uri_port, uri_path)
    return (OBJ in cacheList)

# Cache Control Implementation
def Handle_Cache(uri_path, client_conn):
    """
    This method will control the cache functionality for this Proxy.
    
    The client can enable/disable/flush the cache. When the client
    specifies the path 'proxy/cache/...' this function will be called 
    and control the cache functionality.

    Parameters
    ----------
    uri_path : The path portion of the client URL request (string)

    client_conn : The client connection (socket)
    """

    global cacheList
    global cacheEnabled

    # Handle Cache Control Commands
    if '/proxy/cache/enable' in uri_path:
        cacheEnabled = True
        return
    elif '/proxy/cache/disable' in uri_path:
        cacheEnabled = False
        return
    elif '/proxy/cache/flush' in uri_path and cacheEnabled:
        cacheList.clear()
        return
    else:
        Invalid_HTTP_Request(400, client_conn)

# Blocklist Control Implementation
def Handle_BlockList(uri_path, client_conn):
    """
    This method will control the blocklist functionality for this Proxy.
    
    The client can enable/disable/flush the blocklist. When the client
    specifies the path 'proxy/blocklist/...' this function will be called 
    and control the blocklist functionality.

    The client may add/remove entries from the blocklist given an appended
    string at the end of the path in the request.

    Parameters
    ----------
    uri_path : The path portion of the client URL request (string)

    client_conn : The client connection (socket)
    """

    global blockList
    global blockListEnabled

    # Handle Blocklist Control Commands
    if '/proxy/blocklist/enable' in uri_path:
        blockListEnabled = True
        return
    elif '/proxy/blocklist/disable' in uri_path:
        blockListEnabled = False
        return
    elif '/proxy/blocklist/flush' in uri_path:
        blockList.clear()
        return
    
    # Handle adding or removing objects from the blocklist
    add_path = '/proxy/blocklist/add/'
    remove_path = '/proxy/blocklist/remove/'
    path_split = uri_path.split('/')
    host_name = path_split[-1]
    if add_path in uri_path and blockListEnabled:
        if host_name not in blockList:
            blockList.append(host_name)
        return
    elif remove_path in uri_path and blockListEnabled:
        if host_name in blockList:
            blockList.remove(host_name)
        return
    else:
        Invalid_HTTP_Request(400, client_conn)


# Handles Clients Coming Through Proxy
def Handle_Client_Request(client_conn, client_addr):
    """
    This method is responsible for immediately handling clients' input upon connection to this Proxy.
    
    Client can only use 'GET' requests on HTTP/1.0. It will also handle if the client enables
    or disables the cache/blocklist. If port by client is unspecified, then default port will be 80.

    Parameters
    ----------
    client_conn : The client connection (socket)

    client_addr : The client IP address (_RetAddress)
    """

    # Cache and Blocklist commands
    PROXY_BLOCKLIST_CHECK = 'proxy/blocklist/'
    PROXY_CACHE_CHECK = 'proxy/cache/'

    # URI Information
    URI_PORT = 80 # default is 80
    URI_PATH = ''
    URI_HOSTNAME = ''
    URI_NETLOC = ''

    ''' ----------------- Accept client request ----------------- '''
    sleep(1)
    client_request = ''
    while not client_request.__contains__('\r\n\r\n'):
        curr_input = client_conn.recv(1024).decode('utf-8', errors='ignore')
        client_request += curr_input

    ''' ----------------- Make sure client request is valid first ----------------- '''
    parse_line_request = client_request.split('\r\n')
    parse_request = parse_line_request[0].split(' ')
    parse_len = len(parse_request)
    if parse_len != 3 or client_request == '\r\n\r\n':
        Invalid_HTTP_Request(400, client_conn)

    ''' ----------------- Read additional headers ----------------- '''
    TOTAL_HEADERS = []
    parse_headers = parse_line_request[1:]
    for header in parse_headers:
        if header == '' or header == 'Connection: keep-alive':
            continue

        if ' ' not in header:
            Invalid_HTTP_Request(400, client_conn)

        header_arr = header.split(':')
        header_len = len(header_arr)
        if header_len != 2:
            Invalid_HTTP_Request(400, client_conn)

        TOTAL_HEADERS.append(header)

    ''' ----------------- Grab method information and ensure it is a GET Request, otherwise close connection with client ----------------- '''
    HTTP_method = parse_request[0]
    if HTTP_method is None or HTTP_method == '':
        Invalid_HTTP_Request(400, client_conn)

    if HTTP_method != 'GET':
        Invalid_HTTP_Request(501, client_conn)

    ''' ----------------- 'Grab Host information and ensure it is valid, otherwise close connection with client ----------------- '''
    HTTP_host = parse_request[1]
    uri = urlparse(HTTP_host)
    URI_NETLOC = uri.netloc
    URI_HOSTNAME = uri.hostname
    URI_PATH = uri.path
    if (HTTP_host is None or HTTP_host == '' 
        or URI_NETLOC is None or URI_NETLOC == '' 
        or URI_HOSTNAME is None or URI_HOSTNAME == ''
        or URI_PATH is None or URI_PATH == ''):
            Invalid_HTTP_Request(400, client_conn)

    ''' ----------------- Check for port if specified ----------------- '''
    HTTP_host_port = urlparse(HTTP_host).port
    if HTTP_host_port is not None:
        URI_PORT = HTTP_host_port

    ''' ----------------- Grab http version information and ensure it is HTTP/1.0, otherwise close connection with client ----------------- '''
    HTTP_version = parse_request[2].split('\r\n')[0]
    if HTTP_version != 'HTTP/1.0':
        Invalid_HTTP_Request(400, client_conn)

    ''' ----------------- Check the Cache or Blocklist paths, if they pass, send '200 OK' message ----------------- '''
    if PROXY_CACHE_CHECK in URI_PATH: # Check Cache
        Handle_Cache(URI_PATH, client_conn)
        server_response = 'HTTP/1.0 200 OK\r\n\r\nConnection: close\r\n\r\n'
        client_conn.sendall(server_response.encode())
        client_conn.close()
        return
    elif PROXY_BLOCKLIST_CHECK in URI_PATH: # Check blocklist
        Handle_BlockList(URI_PATH, client_conn)
        server_response = 'HTTP/1.0 200 OK\r\n\r\nConnection: close\r\n\r\n'
        client_conn.sendall(server_response.encode())
        client_conn.close()
        return

    ''' ----------------- Check if Object is in blocklist; block it if true ----------------- '''
    if blockListEnabled:
        for entry in blockList:
            if entry in URI_NETLOC:
                Invalid_HTTP_Request(403, client_conn)

    ''' ----------------- Start Filtering Request ----------------- '''
    Filter_Server_Response(client_conn, URI_HOSTNAME, URI_PORT, URI_PATH, HTTP_method, HTTP_version, TOTAL_HEADERS)
    return

# Program Starts Here. Setup Proxy Server Connection, then wait for Clients to Connect.
def main():
    # Parse out the command line server address and port number to listen to
    parser = OptionParser()
    parser.add_option('-p', type='int', dest='serverPort')
    parser.add_option('-a', type='string', dest='serverAddress')
    (options, args) = parser.parse_args()

    port = options.serverPort
    address = options.serverAddress
    if address is None:
        address = 'localhost'
    if port is None:
        port = 2100

    # Set up signal handling (ctrl-c)
    signal.signal(signal.SIGINT, ctrl_c_pressed)

    # Set up sockets to receive requests
    skt = socket(AF_INET, SOCK_STREAM)
    skt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    skt.bind((address, port))
    skt.listen(100)

    # Accept and handle connections
    # Example: GET http://www.google.com/ HTTP/1.0
    while True:
        client_conn, client_addr = skt.accept()

        # Begin a thread to handle multiple concurrent connections to our Proxy
        Thread(target=Handle_Client_Request, args=(client_conn, client_addr)).start()

if __name__ == '__main__':
    main()