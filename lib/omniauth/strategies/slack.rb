require 'omniauth/strategies/oauth2'
require 'uri'
require 'rack/utils'

module OmniAuth
  module Strategies
    class Slack < OmniAuth::Strategies::OAuth2
      option :name, 'slack'

      option :authorize_options, [:user_scope, :scope, :team]

      option :client_options, {
        site: 'https://slack.com',
        authorize_url: '/oauth/v2/authorize',
        token_url: '/api/oauth.v2.access'
      }

      option :auth_token_params, {
        mode: :query,
        param_name: 'token'
      }

      uid { raw_info['authed_user']['id'] }

      extra do
        {
          bot_user_id: raw_info['bot_user_id'],
          team: raw_info['team'],
        }
      end

      def authorize_params
        super.tap do |params|
          %w[scope team user_scope].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      def raw_info
        access_token
      end


      private

      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end
