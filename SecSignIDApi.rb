#
# SecSign ID Api in ruby.
#
    
SCRIPT_REVISION = '$Revision: 1.2 $'
require 'uri'
require 'net/http'

module SecSign
	class AuthSession

        # No State: Used when the session state is undefined. 
        NOSTATE = 0
        
        # Pending: The session is still pending for authentication.
        PENDING = 1
        
        # Expired: The authentication timeout has been exceeded.
        EXPIRED = 2
        
        # Authenticated: The user was successfully authenticated.
        AUTHENTICATED = 3
        
        # Denied: The user denied this session.
        DENIED = 4
		
        # Suspended: The server suspended this session, because another authentication request was received while this session was still pending.
        SUSPENDED = 5
        
        # Canceled: The service has canceled this session.
        CANCELED = 6
        
        # Fetched: The device has already fetched the session, but the session hasn't been authenticated or denied yet.
        FETCHED = 7
    
        # Invalid: This session has become invalid.
        INVALID = 8
        
        # the secsign id the authentication session has been craeted for
        attr_accessor :secSignID
  		
        # authentication session id
        attr_accessor :authSessionID
       
        # the name of the requesting service. this will be shown at the smartphone
        attr_accessor :requestingServiceName
      
        # the address, a valid url, of the requesting service. this will be shown at the smartphone
        attr_accessor :requestingServiceAddress
       
        # the request ID is similar to a server side session ID. 
        # it is generated after a authentication session has been created. all other request like dispose, withdraw or to get the auth session state
        # will be rejected if a request id is not specified.
        attr_accessor :requestID
       
        # icon data of the so called access pass. the image data needs to be displayed otherwise the user does not know which access apss he needs to choose in order to accept the authentication session.
        attr_accessor :authSessionIconData
       
  
        def createAuthSessionFromHash(authSessionHash)
            @secSignID = authSessionHash['secsignid']
            @authSessionID = authSessionHash['authsessionid']
            @authSessionIconData = authSessionHash['authsessionicondata']
            @requestingServiceName = authSessionHash['servicename']
            @requestingServiceAddress = authSessionHash['serviceaddress']
            @requestID = authSessionHash['requestid']
        end

end # end of class AuthSession
 
         

# Ruby class to connect to a secsign id server. the class will check secsign id server certificate and request for authentication session generation for a given
# user id which is called secsign id. Each authentication session generation needs a new instance of this class.
# 
# $Id: SecSignIDApi.rb,v 1.1 2014/03/10 17:54:45 titus Exp $
# SecSign Technologies Inc.

class SecSignIDApi
        
        @pluginName = nil;
        @lastResponse = nil
        
        # once created the api can be used to create a single request for a certain specified userid
        def initialize()
            # server/secpki hostname and port
            @secSignIDServer = "https://httpapi.secsign.com"
            @secSignIDServerPort = 443
            @secSignIDServer_fallback = "https://httpapi2.secsign.com"
            @secSignIDServerPort_fallback = 443
            
            # script version from cvs revision string
            firstSpace = SCRIPT_REVISION.index(" ")
            lastSpace = SCRIPT_REVISION.index(" ", firstSpace)
            
            @scriptVersion = SCRIPT_REVISION[firstSpace, lastSpace-firstSpace]
            @referer = self.class.name.split('::').last + "_Ruby"
        end
        

        # logs a message if logger instance is not NULL
        def log(message)
            puts message
        end
        
        # Sets an optional plugin name
        def pluginName=(pn)
            @pluginName = pn
        end
        
        # Gets last response
        def response()
            return @lastResponse
        end
        
        #
        #
        # methods for requesting a authentication sessiond and dealing/checking its state
        #
        #
        
        # Send query to secsign id server to create an authentication session for a certain secsign id. This method returns the authentication session itself.
        def requestAuthSession(secsignid, servicename, serviceadress)
            log("Call of function 'requestAuthSession'.")
            
            if servicename.nil?
                log("Parameter servicename must not be nil.")
                raise ArgumentError.new "Parameter servicename must not be nil."
            end
            
            if serviceadress.nil?
                log("Parameter serviceadress must not be nil.")
                raise ArgumentError.new "Parameter serviceadress must not be nil."
            end
            
            if secsignid.nil? 
                log("Parameter secsignid must not be nil.")
                raise ArgumentError.new "Parameter secsignid must not be nil."
            end

            requestParameter = {"request" => 'ReqRequestAuthSession',
                "secsignid" => secsignid,
                "servicename" => servicename,
                "serviceaddress" => serviceadress}
                                      
            if @pluginName.nil?
                requestParameter['pluginname'] = @pluginName
            end
                             
            response = send(requestParameter, nil);
            
            authSession = AuthSession.new
            authSession.createAuthSessionFromHash(response)
            
            return authSession
        end
        
        
        # Gets the authentication session state for a certain secsign id whether the authentication session is still pending or it was accepted or denied.
        def getAuthSessionState(authSession)
            log("Call of function 'getAuthSessionState'.")
            if(authSession.nil? || ! authSession.is_a?(AuthSession))
                message = "Parameter authSession is not an instance of AuthSession. class(authSession)=" + authSession.class
                
                log(message)
                raise ArgumentError.new message
            end
            
            requestParameter = {'request' => 'ReqGetAuthSessionState'}
            response = send(requestParameter, authSession)
            
            return response['authsessionstate']
        end
        
        
        # Cancel the given auth session.
        def cancelAuthSession(authSession)
            log("Call of function 'cancelAuthSession'.")
          	if(authSession.nil? || ! authSession.is_a?(AuthSession))
                message = "Parameter authSession is not an instance of AuthSession. class(authSession)=" + authSession.class
                
                log(message)
                raise ArgumentError.new message
            end
            
            requestParameter = {'request' => 'ReqCancelAuthSession'}
            response = send(requestParameter, authSession)
            
            return response['authsessionstate']
        end
        
        
        # Releases an authentication session if it was accepted and not used any longer
        def releaseAuthSession(authSession)
            log("Call of function 'releaseAuthSession'.")
           	if(authSession.nil? || ! authSession.is_a?(AuthSession))
                message = "Parameter authSession is not an instance of AuthSession. class(authSession)=" + authSession.class
                
                log(message)
                raise ArgumentError.new message
            end
            
            requestParameter = {'request' => 'ReqReleaseAuthSession'}
            response = send(requestParameter, authSession)
            
            return response['authsessionstate']
        end
        
        
        # build a dictionary with all parameters which has to be send to server
        def buildParameterDict(parameter, authSession)
            #mandatoryParams = {'apimethod' => @referer, 'scriptversion' => @scriptVersion}
            mandatoryParams = {'apimethod' => @referer}
            if(! authSession.nil?)
                # add auth session data to mandatory parameter array
                authSessionData = {'secsignid' => authSession.secSignID,
                                         'authsessionid'  => authSession.authSessionID,
                                         'requestid' => authSession.requestID}
                
                mandatoryParams.merge!(authSessionData)
            end
            return mandatoryParams.merge(parameter)
        end
        
        
        
        # sends given parameters to secsign id server and wait given amount
        # of seconds till the connection is timed out
        def send(parameter, authSession)
            requestParamDict = buildParameterDict(parameter, authSession)
            requestQuery = requestParamDict.map{|k,v| "#{URI.escape(k.to_s)}=#{URI.escape(v.to_s)}"} * "&"
            timeout_in_seconds = 15

            # create http request
            response = nil
            #response = postData(@secSignIDServer, @secSignIDServerPort, requestParamDict, timeout_in_seconds)
            
            # check if output is nil. in that case the secsign id might not have been reached.
            if(response.nil?)

                log("http request: response is nil. Server #{@secSignIDServer}:#{@secSignIDServerPort} has not been reached.")
                
                if(! @secSignIDServer_fallback.nil?)
                    log("http request: create new request to fallback server.")
                    # response = postData(@secSignIDServer_fallback, @secSignIDServerPort_fallback, requestParamDict, timeout_in_seconds)
                    
					if(response.nil?)
                        log("http request: response is nil. Fallback server #{@secSignIDServer_fallback}:#{@secSignIDServerPort_fallback} has not been reached.")
                        raise ArgumentError.new "http request error: can't connect to server"
                    end
                else 
                    log("http request: no fallback server has been specified.");
                end
            end

            log("http request response: " + (response.nil? ? "nil" : response))
            @lastResponse = response
            
            return checkResponse(response) # will throw an exception in case of an error
        end
        
        
        # checks the secsign id server response string
        def checkResponse(response)
            if(response.nil?)
                log("Could not connect to host '" + @secSignIDServer + ":" + @secSignIDServerPort + "'")
                raise ArgumentError.new "Could not connect to server."
            end
            
            # server send parameter strings like:
            # var1=value1&var2=value2&var3=value3&...
            responseArray = response.split(/&/).inject(Hash.new{|h,key|h[key]=[]}) do |h, s|
								key,value = s.split(/=/)
								h[key] << value
								h
							end
            
            # check if server send a parameter named 'error'
            if(responseArray['error'].nil?)
                log("SecSign ID server sent error. code=" + responseArray['error'] + " message=" + responseArray['errormsg'])
                raise ArgumentError.new(responseArray['errormsg'], responseArray['error'])
            end
            return responseArray
        end
        
        
        # Post data to server
        def postData(server, port, parameter, timeout_in_seconds)
			http = Net::HTTP.new(server, port)
			request = Net::HTTP::Post.new("/method_name")
			request.set_form_data(parameter)
 			
 			return http.request(request) 
        end
        
        private :log
        private :checkResponse
        private :send
        private :buildParameterDict
        private :postData
	end # end of class SecSignIDApi
end # end of module SecSign