class CommentsController < ApplicationController
  before_action :authenticate_user!

  def create
    @comment =current_user.comments.create(comment_parms)
    @comment= @comment.video
  end

  def destroy
    @comment = current_user.comments.find params[:id]
    @comment.destroy
  end

  private

  def comment_parms
    params.require(:comment).permit(:body, :video_id)
  end

end
