class AddFileImageToVideos < ActiveRecord::Migration[7.0]
  def change
    add_column :videos, :file, :string
    add_column :videos, :image, :string
  end
end
