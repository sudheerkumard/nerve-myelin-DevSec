# Fixture for engine/myelin_engine/rules/sast/ruby.yaml (opengrep --test). Not executed.
class UsersController < ApplicationController
  def index
    # ruleid: nervve.ruby.sql-injection
    @users = User.where("name = '#{params[:q]}'")
    # ok: nervve.ruby.sql-injection
    @users = User.where("name = ?", params[:q])
  end

  def ping
    # ruleid: nervve.ruby.command-injection
    system("ping -c 1 #{params[:host]}")
    # ok: nervve.ruby.command-injection
    system("ping", "-c", "1", params[:host])
  end

  def load
    # ruleid: nervve.ruby.unsafe-deserialisation
    Marshal.load(params[:blob])
  end

  def file
    # ruleid: nervve.ruby.path-traversal
    send_file("/srv/files/" + params[:name])
    # ok: nervve.ruby.path-traversal
    send_file("/srv/files/" + File.basename(params[:name]))
  end

  def go
    # ruleid: nervve.ruby.open-redirect
    redirect_to params[:next]
  end

  def show
    # ruleid: nervve.ruby.xss
    @bio = params[:bio].html_safe
  end
end

# ruleid: nervve.ruby.ssl-verify-none
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
