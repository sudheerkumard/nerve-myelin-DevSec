# Fixture for engine/myelin_engine/rules/sast/ruby_hardening.yaml (opengrep --test).
class UsersController < ApplicationController
  # ruleid: nervve.ruby.csrf-disabled
  skip_before_action :verify_authenticity_token
  def update
    # ruleid: nervve.ruby.mass-assignment
    @user.update(params.permit!)
    # ok: nervve.ruby.mass-assignment
    @user.update(params.require(:user).permit(:name))
    # ruleid: nervve.ruby.ssrf
    body = Net::HTTP.get(URI(params[:url]))
    # ruleid: nervve.ruby.weak-crypto
    h = Digest::MD5.hexdigest(params[:x])
  end
end
# ruleid: nervve.ruby.insecure-session-config
config.force_ssl = false
