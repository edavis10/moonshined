server 'ms', :app, :web, :db, :primary => true

set :branch, "debian"

namespace :deploy do
  task :restart do
    # no-op
  end
end
