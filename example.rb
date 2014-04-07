#!/usr/bin/ruby

require_relative 'SecSignIDApi' 

#
#
# Example how to retrieve an authentication session, ask its status and withdraw the authentication session.
#
#	
    
#
# Create an instance of SecSignIDApi.
#
puts "create new instance of SecSignIDApi."
secSignIDApi = SecSign::SecSignIDApi.new
authSession =  SecSign::AuthSession.new
#
# The servicename and address is mandatory. It has to be send to the server.
# The value of $servicename will be shown on the display of the smartphone. The user then can decide whether he accepts the authentication session shown on his mobile phone.
#
servicename = "Your Website Login";
serviceaddress = "http://www.yoursite.com/";
secsignid = "username";
    
#
# Get a auth session for the sepcified SecSign ID
#
# If $secsignid is null or empty an exception is thrown.
# If $servicename is null or empty an exception is thrown.
#
begin
	authSession = secSignIDApi.requestAuthSession(secsignid, servicename, serviceaddress)
    puts "got authSession '#{authSession}'"
rescue
    puts "could not get an authentication session for SecSign ID '#{secsignid}' : #{$!}"
    exit
end
    
#
# Get the auth session status
#
# If $authSession is null or not an instance of AuthSession an exception is thrown
#
$authSessionState = SecSign::AuthSession::NOSTATE
begin
   	$authSessionState = secSignIDApi.getAuthSessionState(authSession)
	puts "got auth session state: #{$authSessionState}";
rescue
    puts "could not get status for authentication session '#{authSession.authSessionID}' : #{$!}"
    exit
end
    
    
    
# If the script shall wait till the user has accepted the auth session or denied it,  it has to ask the server frequently
secondsToWaitUntilNextCheck = 10
noError = true
	
while(($authSessionState == SecSign::AuthSession::PENDING || $authSessionState == SecSign::AuthSession::FETCHED) && noError) do
    begin
	  	$authSessionState = secSignIDApi.getAuthSessionState(authSession)
		puts "got auth session state: #{$authSessionState}";
	rescue
		puts "could not get status for authentication session '#{authSession.authSessionID}' : #{$!}"
		noError = false
	end
end
    
if($authSessionState == SecSign::AuthSession::AUTHENTICATED)
    puts "user has accepted the auth session '" + authSession.authSessionID + "'."
    secSignIDApi.releaseAuthSession(authSession)
    puts "auth session '#{authSession.authSessionID}' was released."
    
elsif($authSessionState == SecSign::AuthSession::DENIED)
    puts "user has denied the auth session '#{authSession.authSessionID}'."
    
    # after the auth session is successfully canceled it is not possible to inquire the status again
    $authSessionState = secSignIDApi.cancelAuthSession(authSession)
    
    if($authSessionState == SecSign::AuthSession::CANCELED)
        puts "authentication session successfully cancelled..."
    end
else 
    puts "auth session '#{authSession.authSessionID}' has state '#{$authSessionState}'."
        
    # after the auth session is successfully canceled it is not possible to inquire the status again
    $authSessionState = secSignIDApi.cancelAuthSession(authSession)
	if($authSessionState == SecSign::AuthSession::CANCELED)
    	puts "authentication session successfully cancelled..."
    end
end
 
# end of example
