# frozen_string_literal: true

require 'helper'
require 'fluent/plugin/filter_logs.rb'

class LogsFilterTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogsFilter).configure(conf)
  end

  def filter(messages, conf = '')
    d = create_driver(conf)
    d.run(default_tag: 'input.access') do
      messages.each do |message|
        d.feed(message)
      end
    end
    d.filtered_records
  end

  test 'basic unformated message' do
    messages = [
      { 'message' => 'This is test message' }
    ]
    expected = [
      { 'message' => 'This is test message' }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'basic fmtlog parsing' do
    messages = [
      { 'message' => 'time="2018-01-01 00:00:00" aaa=111 bbb=222' }
    ]
    expected = [
      { 'message' => 'time="2018-01-01 00:00:00" aaa=111 bbb=222' }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json fmt logs' do
    text = '{"container_id":"2caa236b7c","container_name":"/traefik-lb_traefik_1","source":"stdout","log":"time=\"2020-03-31T08:46:44Z\" level=debug msg=\"Filtering disabled container\" providerName=docker container=deposit-collection-edge-11facecb13"}'
    messages = [
      JSON.parse(text)
    ]
    expected = [
      {
        'container_id' => '2caa236b7c',
        'container_name' => '/traefik-lb_traefik_1',
        'source' => 'stdout',
        'level' => 'DEBUG',
        'message' => 'Filtering disabled container',
        'providerName' => 'docker',
        'container' => 'deposit-collection-edge-11facecb13',
        'timestamp' => 1_585_644_404
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json apache logs (nginx example)' do
    text = '{"container_name":"/demo_frontend_1","source":"stdout","log":"192.168.80.32 - - [27/Mar/2020:19:26:18 +0000] \"GET /static/media/search.f6cf3254.svg HTTP/1.1\" 200 329 \"https://demo.openware.work/trading/copyright/batusdt\" \"Mozilla/5.0 (Linux; Android 8.0.0; SAMSUNG SM-J330FN/J330FNXXS3BSE1) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/11.1 Chrome/75.0.3770.143 Mobile Safari/537.36\" \"123.456.789.0\"","container_id":"1888b6a06ef7"}'
    messages = [
      JSON.parse(text)
    ]
    expected = [
      {
        'container_id' => '1888b6a06ef7',
        'container_name' => '/demo_frontend_1',
        'content_size' => '329',
        'referer' => 'https://demo.openware.work/trading/copyright/batusdt',
        'message' => 'GET /static/media/search.f6cf3254.svg HTTP/1.1',
        'source' => 'stdout',
        'status_code' => '200',
        'timestamp' => 1_585_337_178,
        'upstream_ip' => '192.168.80.32',
        'user_agent' => 'Mozilla/5.0 (Linux; Android 8.0.0; SAMSUNG SM-J330FN/J330FNXXS3BSE1) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/11.1 Chrome/75.0.3770.143 Mobile Safari/537.36',
        'user_ip' => '123.456.789.0'
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json apache logs (influx example)' do
    text = '{"source":"stderr","log":"[httpd] 192.168.128.5 - root [31/Mar/2020:08:26:58 +0000] \"GET /query?db=peatio_production&epoch=s&p=%5BREDACTED%5D&precision=s&q=SELECT+%2A+FROM+candles_3d+WHERE+market%3D%27ethusd%27+ORDER+BY+desc+LIMIT+1 HTTP/1.1\" 200 181 \"-\" \"Ruby\" 6371fccd-7329-11ea-aef5-0242c0a8800b 384","container_id":"c0f3b3778","container_name":"/dev01_influxdb_1"}'
    messages = [
      JSON.parse(text)
    ]
    expected = [
      {
        'container_id' => 'c0f3b3778',
        'container_name' => '/dev01_influxdb_1',
        'content_size' => '181',
        'referer' => '-',
        'message' => 'GET /query?db=peatio_production&epoch=s&p=%5BREDACTED%5D&precision=s&q=SELECT+%2A+FROM+candles_3d+WHERE+market%3D%27ethusd%27+ORDER+BY+desc+LIMIT+1 HTTP/1.1',
        'source' => 'stderr',
        'status_code' => '200',
        'timestamp' => 1_585_643_218,
        'upstream_ip' => '192.168.128.5',
        'user_agent' => 'Ruby'
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json vault logs (with level)' do
    text = '{"container_name":"/demo_vault_1","source":"stderr","log":"2020-03-30T09:53:21.323Z [WARN]  no `api_addr` value specified in config or in VAULT_API_ADDR; falling back to detection if possible, but this value should be manually set","container_id":"4f82763814e"}'
    messages = [
      JSON.parse(text)
    ]
    expected = [
      {
        'container_id' => '4f82763814e',
        'container_name' => '/demo_vault_1',
        'level' => 'WARN',
        'message' => ' no `api_addr` value specified in config or in VAULT_API_ADDR; falling back to detection if possible, but this value should be manually set',
        'source' => 'stderr',
        'timestamp' => 1_585_562_001
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json vault logs (unformated)' do
    text = '{"container_name":"/demo_vault_1","source":"stdout","log":"Version: Vault v1.3.0","container_id":"4f82763814e"}'
    messages = [
      JSON.parse(text)
    ]
    expected = [
      {
        'container_id' => '4f82763814e',
        'container_name' => '/demo_vault_1',
        'message' => 'Version: Vault v1.3.0',
        'source' => 'stdout'
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json ranger logs (prometheus format unmanaged)' do
    text = '{"log":"ranger_connections_total{auth=\"public\"}: 3","container_id":"545d74a168d","container_name":"/demo_ranger_1","source":"stderr"}'
    messages = [
      JSON.parse(text)
    ]
    expected = [
      {
        'container_id' => '545d74a168d',
        'container_name' => '/demo_ranger_1',
        'message' => 'ranger_connections_total{auth="public"}: 3',
        'source' => 'stderr'
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json rabbitmq logs' do
    text = '{"source":"stdout","log":"2020-03-30 09:54:51.627 [info] <0.734.0> connection <0.734.0> (192.168.128.5:49388 -> 192.168.128.4:5672): user \'guest\' authenticated and granted access to vhost \'/\'","container_id":"40b5e1bde","container_name":"/dev01_rabbitmq_1"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '40b5e1bde',
        'container_name' => '/dev01_rabbitmq_1',
        'message' => '<0.734.0> connection <0.734.0> (192.168.128.5:49388 -> 192.168.128.4:5672): user \'guest\' authenticated and granted access to vhost \'/\'',
        'source' => 'stdout',
        'level' => 'INFO',
        'timestamp' => 1_585_562_091
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json ruby (json error simple)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_blockchain_1","source":"stderr","log":"{\"level\":\"ERROR\",\"time\":\"2020-03-31 21:54:05\",\"message\":\"#<Peatio::Blockchain::ClientError: Failed to open TCP connection to parity:8545 (getaddrinfo: Name or service not known)>\"}"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_blockchain_1',
        'message' => '#<Peatio::Blockchain::ClientError: Failed to open TCP connection to parity:8545 (getaddrinfo: Name or service not known)>',
        'source' => 'stderr',
        'level' => 'ERROR',
        'timestamp' => 1_585_691_645
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json ruby (json error 2)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_blockchain_1","source":"stderr","log":"{\"level\":\"ERROR\",\"time\":\"2020-03-31 21:55:56\",\"message\":\"/home/app/lib/peatio/ethereum/blockchain.rb:60:in `rescue in latest_block_number\'\\\\n/home/app/lib/peatio/ethereum/blockchain.rb:57:in `latest_block_number\'\\\\n/home/app/app/services/blockchain_service.rb:16:in `latest_block_number\'\\\\n/home/app/app/workers/daemons/blockchain.rb:22:in `process\'\\\\n/home/app/app/workers/daemons/blockchain.rb:9:in `block (3 levels) in run\'\"}"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_blockchain_1',
        'message' =>
          "/home/app/lib/peatio/ethereum/blockchain.rb:60:in `rescue in latest_block_number'\n" \
          "/home/app/lib/peatio/ethereum/blockchain.rb:57:in `latest_block_number'\n" \
          "/home/app/app/services/blockchain_service.rb:16:in `latest_block_number'\n" \
          "/home/app/app/workers/daemons/blockchain.rb:22:in `process'\n" \
          "/home/app/app/workers/daemons/blockchain.rb:9:in `block (3 levels) in run'",
        'source' => 'stderr',
        'level' => 'ERROR',
        'timestamp' => 1_585_691_756
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json ruby (logger example debug)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_blockchain_1","source":"stderr","log":"D, [2020-04-01T13:04:30.445223 #1] DEBUG -- : received websocket message: [156,\\"te\\",[431756335,1585746269293,0.6,131.83]]"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_blockchain_1',
        'message' => 'received websocket message: [156,"te",[431756335,1585746269293,0.6,131.83]]',
        'source' => 'stderr',
        'level' => 'DEBUG',
        'timestamp' => 1_585_746_270
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json ruby (logger example info 1)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_blockchain_1","source":"stderr","log":"I, [2020-04-01T13:04:30.471779 #1] INFO -- : Publishing trade event: {\\"tid\\"=>431756335, \\"amount\\"=>0.6e0, \\"price\\"=>131.83, \\"date\\"=>1585746269, \\"taker_type\\"=>\\"buy\\"\\}"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_blockchain_1',
        'message' => 'Publishing trade event: {"tid"=>431756335, "amount"=>0.6e0, "price"=>131.83, "date"=>1585746269, "taker_type"=>"buy"}',
        'source' => 'stderr',
        'level' => 'INFO',
        'timestamp' => 1_585_746_270
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json ruby (logger example info 2)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_blockchain_1","source":"stderr","log":"I, [2020-04-01T18:47:00.480183 #1]  INFO -- : [3ce041fb-32f9-462b-950b-34e1ba4904f7] Completed 200 OK in 7ms (Views: 5.6ms | Allocations: 6356)"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_blockchain_1',
        'message' => '[3ce041fb-32f9-462b-950b-34e1ba4904f7] Completed 200 OK in 7ms (Views: 5.6ms | Allocations: 6356)',
        'source' => 'stderr',
        'level' => 'INFO',
        'timestamp' => 1_585_766_820
      }
    ]
    assert_equal(expected, filter(messages))
  end
end
