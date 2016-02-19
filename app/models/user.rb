class User < ActiveRecord::Base
  def user_params
    params.require(:user).permit(:username, :email, :password, :password_confirmation)
  end
  
  before_save :encrypt_password
  after_save :clear_password
  
  def encrypt_password
    if password.present?
      self.salt = BCrypt::Engine.generate_salt
      self.encrypted_password = BCrypt::Engine.hash_secret(password, salt)
    end
  end
  def clear_password
    self.password = nil
  end
  
  attr_accessor :password, :user, :password_confirmation, :email
  EMAIL_REGEX = /A[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}z/i
  validates :username, :presence => true, :uniqueness => true, :length => { :in => 3..20 }
  validates :email, :presence => true, :uniqueness => true, :format => EMAIL_REGEX
  validates :password, :confirmation => true, :uniqueness => true
  validates_length_of :password, :in => 6..20, :on => :create
end
