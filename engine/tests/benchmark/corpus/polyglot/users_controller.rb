class UsersController < ApplicationController
  def search
    User.where("name = '#{params[:name]}'")         # VULN NM-SAST-039
    User.where(name: params[:name])                 # SAFE hash conditions
    system("convert #{params[:file]}")              # VULN NM-SAST-040
    system("convert", params[:file])                # SAFE argument list
  end
end
