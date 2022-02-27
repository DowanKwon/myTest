# frozen_string_literal: true

class Api::AuthenticationController < Devise::SessionsController

  ##//added by KDW
  attr_reader :current_user
  ##before_action :jwt_authenticate_request! ##여기서 걸림 그럼 다른 곳에 클래스를 만들고, 해당 클래스를 상속받으면 어떨까?
  protected

  ## JWT 토큰 검증
  def jwt_authenticate_request!
    ## 토큰 안에 user id 정보가 있는지 확인 / 없을 시 error response 반환
    unless user_id_in_token?
      render json: { errors: ['Not Authenticated!']}, status: :unauthorized ##해당 오류 발생
      return
    end
    ##render json: { http_token: http_token, auth_token: JWT.decode(http_token, ENV["DEVISE_JWT_SECRET_KEY"])[0] }
    ## Token 안에 있는 user_id 값을 받아와서 User 모델의 유저 정보 탐색
    @current_user = User.find(auth_token[:user_id])
  rescue JWT::VerificationError, JWT::DecodeError
    render json: { errors: ['Not Authenticated'], http_token: http_token }, status: :unauthorized
  end

  private

  ## 헤더에 있는 정보 중, Authorization 내용(토큰) 추출
  def http_token
    http_token ||= if request.headers['Authorization'].present?
      request.headers['Authorization'].split(' ').last
    end
  end

  ## 토큰 해석 : 토큰 해석은 lib/json_web_token.rb 내의 decode 메소드에서 진행됩니다.
  def auth_token
    auth_token ||= JsonWebToken.decode(http_token)
  end

  ## 토큰 해석 후, Decode 내용 중 User id 정보 확인
  def user_id_in_token?
    http_token && auth_token && auth_token[:user_id].to_i
  end
  ##
  ## JWT 토큰 생성을 위한 Devise 유저 정보 검증
  def authenticate_user
    ## body로 부터 받은 json 형식의 params를 parsing
    json_params = JSON.parse(request.body.read)

    user = User.find_for_database_authentication(email: json_params["auth"]["email"])
    if user.valid_password?(json_params["auth"]["password"])
      render json: payload(user)
    else
      render json: {errors: ['Invalid Username/Password']}, status: :unauthorized
    end
  end

  private

  ## Response으로서 보여줄 json 내용 생성 및 JWT Token 생성
  def payload(user)
    ## 해당 코드 예제에서 토큰 만료기간은 '30일' 로 설정
    @token = JWT.encode({ user_id: user.id, exp: 30.days.from_now.to_i }, ENV["DEVISE_JWT_SECRET_KEY"])
    @tree = { :userInfo => {id: user.id, email: user.email} }
    response.headers['Authorization'] = @token
    return @tree
  end
  ##

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
