server 'ms', :app, :web, :db, :primary => true

namespace :deploy do
  task :restart do
    # no-op
  end
end
