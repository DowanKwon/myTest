class CreateVideos < ActiveRecord::Migration[7.0]
  def change
    create_table :videos do |t|
      t.text :title
      t.text :description
      t.references :user, null: false, foreign_key: true
      t.integer :view_count

      t.timestamps
    end
    add_index :videos, :view_count
  end
end
