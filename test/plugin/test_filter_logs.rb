require "helper"
require "fluent/plugin/filter_logs.rb"

class LogsFilterTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  test "failure" do
    flunk
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogsFilter).configure(conf)
  end
end
