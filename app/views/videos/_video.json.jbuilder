json.extract! video, :id, :title, :description, :user_id, :view_count, :created_at, :updated_at
json.url video_url(video, format: :json)
