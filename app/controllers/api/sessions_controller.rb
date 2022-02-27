# frozen_string_literal: true

class Api::SessionsController < Api::AuthenticationController
  skip_before_action :verify_authenticity_token
  protect_from_forgery with: :null_session
  before_action :jwt_authenticate_request!, except: :create
  before_action :authenticate_user, only: :create
  respond_to :json

  def test
    @dataJson = { :message => "[Test] Token 인증 되었습니다! :D", :user => current_user }
    render :json => @dataJson, :except => [:id, :created_at, :updated_at]
  end

  private

  def respond_with(resource, _opts = {})
    render json: {
      status: {code: 200, message: 'Logged in sucessfully.'},
      data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
    }, status: :ok
  end

  def respond_to_on_destroy
    if current_user
      render json: {
        status: 200,
        message: "logged out successfully"
      }, status: :ok
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end
  # GET /resource/sign_in
  # def new
  #   super
  # end

  # POST /resource/sign_in
  # def create
  #   super
  # end

  # DELETE /resource/sign_out
  # def destroy
  #   super
  # end

  # protected

  # If you have extra params to permit, append them to the sanitizer.

end
