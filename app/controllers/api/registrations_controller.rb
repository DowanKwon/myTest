class Api::RegistrationsController < Devise::RegistrationsController
  before_action :configure_sign_up_params, only: [:create]
  protect_from_forgery with: :null_session
  skip_before_action :verify_authenticity_token

  respond_to :json

  private

  def respond_with(resource, _opts = {})
    if resource.persisted?
      render json: {
        status: {code: 200, message: 'Signed up sucessfully.'},
        data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
      }
    else
      render json: {
        status: {message: "User couldn't be created successfully. #{resource.errors.full_messages.to_sentence}"}
      }, status: :unprocessable_entity
    end
  end


  protected

  def configure_sign_up_params
    devise_parameter_sanitizer.permit(:sign_up, keys: [:name, :subname, :gender, :birth])
  end


end
