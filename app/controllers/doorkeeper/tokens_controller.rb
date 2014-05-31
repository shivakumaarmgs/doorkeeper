module Doorkeeper
  class TokensController < ::Doorkeeper::ApplicationController
    include Helpers::Controller
    include ActionController::RackDelegation
    include ActionController::Instrumentation

    before_filter :authenticate_sms, only: [:create]

    def create
      response = strategy.authorize
      self.headers.merge! response.headers
      self.response_body = response.body.to_json
      self.status        = response.status
    rescue Errors::DoorkeeperError => e
      handle_token_exception e
    end

    #############################################
    #   RFC 7009 - OAuth 2.0 Token Revocation   #
    #                                           #
    #    http://tools.ietf.org/html/rfc7009     #
    #############################################
    def revoke
      # The authorization server first validates the client credentials
      if doorkeeper_token && doorkeeper_token.accessible?
        # Doorkeeper does not use the token_type_hint logic described in the RFC 7009
        # due to the refresh token implementation that is a field in the access token model.
        revoke_token(request.POST['token']) if request.POST['token']
      end
      # The authorization server responds with HTTP status code 200 if the
      # token has been revoked sucessfully or if the client submitted an invalid token
      render json: {}, status: 200
    end

    private

    def revoke_token(token)
      token = Doorkeeper::AccessToken.authenticate(token) || Doorkeeper::AccessToken.by_refresh_token(token)
      if token && doorkeeper_token.same_credential?(token)
        token.revoke
        true
      else
        false
      end
    end

    def strategy
      @strategy ||= server.token_request params[:grant_type]
    end

    def authenticate_sms
      if params[:grant_type] != "refresh_token"
        puts "======================#{current_resource_owner.first_name}"
        if params[:otp_pin] != current_resource_owner.pin
          render json: { "error" => "invalid otp" }, status: 200
        end
      end
    end
    #def current_parent_resource=(parent)
    #@current_parent = parent
    #end

    #def current_parent_resource
    #remember_token = Parent.digest(cookies[:remember_token])
    #@current_parent ||= Parent.find_by(remember_token: remember_token)
    #end
  end
end
