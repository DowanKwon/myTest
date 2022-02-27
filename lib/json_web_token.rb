#added by KDW
class JsonWebToken
  def self.decode(token)
    return HashWithIndifferentAccess.new(JWT.decode(token, ENV["DEVISE_JWT_SECRET_KEY"])[0])
  rescue
    nil
  end
end
