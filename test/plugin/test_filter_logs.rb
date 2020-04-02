# frozen_string_literal: true

require 'byebug'
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
    text = '{"container_name":"/demo_vault_1","source":"stderr","log":"2020-03-30T09:53:21.323Z [WARNING]  no `api_addr` value specified in config or in VAULT_API_ADDR; falling back to detection if possible, but this value should be manually set","container_id":"4f82763814e"}'
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

  test 'json rabbitmq logs' do
    text = '{"source":"stdout","log":"2020-03-30 09:54:51.627 [note] <0.734.0> connection <0.734.0> (192.168.128.5:49388 -> 192.168.128.4:5672): user \'guest\' authenticated and granted access to vhost \'/\'","container_id":"40b5e1bde","container_name":"/dev01_rabbitmq_1"}'
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

  test 'json parity (block imported)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_parity_1","source":"stderr","log":"2020-04-02 08:00:53 UTC Verifier #7 INFO import Imported #17687508 0xf356…d999 (0 txs, 0.00 Mgas, 1 ms, 0.58 KiB) + another 1 block(s) containing 0 tx(s)"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_parity_1',
        'message' => 'Verifier #7 INFO import Imported #17687508 0xf356…d999 (0 txs, 0.00 Mgas, 1 ms, 0.58 KiB) + another 1 block(s) containing 0 tx(s)',
        'source' => 'stderr',
        'level' => 'INFO',
        'timestamp' => 1_585_814_453
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json parity (peer report ok)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_parity_1","source":"stderr","log":"2020-04-02 08:00:53 UTC IO Worker #0 INFO import 19/50 peers 6 MiB chain 10 MiB db 0 bytes queue 19 KiB sync RPC: 0 conn, 122 req/s, 856 µs"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_parity_1',
        'message' => 'IO Worker #0 INFO import 19/50 peers 6 MiB chain 10 MiB db 0 bytes queue 19 KiB sync RPC: 0 conn, 122 req/s, 856 µs',
        'peers' => '19',
        'peers_max' => '50',
        'source' => 'stderr',
        'level' => 'INFO',
        'timestamp' => 1_585_814_453
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json parity (peer report warn)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_parity_1","source":"stderr","log":"2020-04-02 08:00:53 UTC IO Worker #0 INFO import 10/50 peers 6 MiB chain 10 MiB db 0 bytes queue 19 KiB sync RPC: 0 conn, 122 req/s, 856 µs"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_parity_1',
        'message' => 'IO Worker #0 INFO import 10/50 peers 6 MiB chain 10 MiB db 0 bytes queue 19 KiB sync RPC: 0 conn, 122 req/s, 856 µs',
        'peers' => '10',
        'peers_max' => '50',
        'source' => 'stderr',
        'level' => 'WARN',
        'timestamp' => 1_585_814_453
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json parity (peer report error)' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_parity_1","source":"stderr","log":"2020-04-02 08:00:53 UTC IO Worker #0 INFO import 5/50 peers 6 MiB chain 10 MiB db 0 bytes queue 19 KiB sync RPC: 0 conn, 122 req/s, 856 µs"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_parity_1',
        'message' => 'IO Worker #0 INFO import 5/50 peers 6 MiB chain 10 MiB db 0 bytes queue 19 KiB sync RPC: 0 conn, 122 req/s, 856 µs',
        'peers' => '5',
        'peers_max' => '50',
        'source' => 'stderr',
        'level' => 'ERROR',
        'timestamp' => 1_585_814_453
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json ranger metrics 1' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_ranger_1","source":"stderr","log":"ranger_connections_total{auth=\\"public\\"}: 44"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_ranger_1',
        'message' => 'ranger_connections_total{auth="public"}: 44',
        'source' => 'stderr',
        'level' => 'INFO'
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json ranger metrics 2' do
    text = '{"container_id":"7d3ac22","container_name":"/dev01_ranger_1","source":"stderr","log":"ranger_subscriptions_current: 0"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/dev01_ranger_1',
        'message' => 'ranger_subscriptions_current: 0',
        'source' => 'stderr',
        'level' => 'INFO'
      }
    ]
    assert_equal(expected, filter(messages))
  end

  test 'json rails grappe debug logs' do
    text = '{"container_id":"7d3ac22","container_name":"/demo_barong_1","source":"stdout","date":"2020-04-02T14:05:44.550+00:00","severity":"WARN","data":{"status":200,"time":{"total":3.09,"db":0.71,"view":2.38},"method":"DELETE","path":"/api/v2/identity/sessions","params":{},"host":"wiprex.openware.work","response":[200],"ip":"","ua":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36 OPR/67.0.3575.97","headers":{"Version":"HTTP/1.1","Host":"wiprex.openware.work","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36 OPR/67.0.3575.97","Accept":"application/json, text/plain, */*","Accept-Encoding":"gzip, deflate, br","Accept-Language":"en-GB,en-US;q=0.9,en;q=0.8","Cookie":"_ga=GA1.2.234775274.1582223639; _barong_session=1c67047cf6e58f69ec75eed56c66d652","Origin":"https://wiprex.openware.work","Referer":"https://wiprex.openware.work/tower/users/user-directory/IDBA90D58E76/main","Sec-Fetch-Dest":"empty","Sec-Fetch-Mode":"cors","Sec-Fetch-Site":"same-origin","X-Forwarded-For":"","X-Forwarded-Host":"wiprex.openware.work","X-Forwarded-Port":"443","X-Forwarded-Proto":"https","X-Forwarded-Server":"2caa236b7c38","X-Real-Ip":"93.73.59.123","X-Request-Id":"855cfd0a-2796-4bc1-a5a9-2c5e776bcdaa","X-Envoy-Expected-Rq-Timeout-Ms":"15000","X-Envoy-Original-Path":"/api/v2/barong/identity/sessions"}},"message":"{\"date\":\"2020-04-02T14:05:44.550+00:00\",\"severity\":\"WARN\",\"data\":{\"status\":200,\"time\":{\"total\":3.09,\"db\":0.71,\"view\":2.38},\"method\":\"DELETE\",\"path\":\"/api/v2/identity/sessions\",\"params\":{},\"host\":\"wiprex.openware.work\",\"response\":[200],\"ip\":\"\",\"ua\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36 OPR/67.0.3575.97\",\"headers\":{\"Version\":\"HTTP/1.1\",\"Host\":\"wiprex.openware.work\",\"User-Agent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36 OPR/67.0.3575.97\",\"Accept\":\"application/json, text/plain, */*\",\"Accept-Encoding\":\"gzip, deflate, br\",\"Accept-Language\":\"en-GB,en-US;q=0.9,en;q=0.8\",\"Cookie\":\"_ga=GA1.2.234775274.1582223639; _barong_session=1c67047cf6e58f69ec75eed56c66d652\",\"Origin\":\"https://wiprex.openware.work\",\"Referer\":\"https://wiprex.openware.work/tower/users/user-directory/IDBA90D58E76/main\",\"Sec-Fetch-Dest\":\"empty\",\"Sec-Fetch-Mode\":\"cors\",\"Sec-Fetch-Site\":\"same-origin\",\"X-Forwarded-For\":\"\",\"X-Forwarded-Host\":\"wiprex.openware.work\",\"X-Forwarded-Port\":\"443\",\"X-Forwarded-Proto\":\"https\",\"X-Forwarded-Server\":\"2caa236b7c38\",\"X-Real-Ip\":\"93.73.59.123\",\"X-Request-Id\":\"855cfd0a-2796-4bc1-a5a9-2c5e776bcdaa\",\"X-Envoy-Expected-Rq-Timeout-Ms\":\"15000\",\"X-Envoy-Original-Path\":\"/api/v2/barong/identity/sessions\"}}}"}'
    messages = [
      JSON.parse(text)
    ]

    expected = [
      {
        'container_id' => '7d3ac22',
        'container_name' => '/demo_barong_1',
        'date' => '2020-04-02T14:05:44.550+00:00',
        'level' => 'DEBUG',
        'message' => '{"status":200,"time":{"total":3.09,"db":0.71,"view":2.38},"method":"DELETE","path":"/api/v2/identity/sessions","params":{},"host":"wiprex.openware.work","response":[200],"ip":"","ua":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36 OPR/67.0.3575.97","headers":{"Version":"HTTP/1.1","Host":"wiprex.openware.work","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36 OPR/67.0.3575.97","Accept":"application/json, text/plain, */*","Accept-Encoding":"gzip, deflate, br","Accept-Language":"en-GB,en-US;q=0.9,en;q=0.8","Cookie":"_ga=GA1.2.234775274.1582223639; _barong_session=1c67047cf6e58f69ec75eed56c66d652","Origin":"https://wiprex.openware.work","Referer":"https://wiprex.openware.work/tower/users/user-directory/IDBA90D58E76/main","Sec-Fetch-Dest":"empty","Sec-Fetch-Mode":"cors","Sec-Fetch-Site":"same-origin","X-Forwarded-For":"","X-Forwarded-Host":"wiprex.openware.work","X-Forwarded-Port":"443","X-Forwarded-Proto":"https","X-Forwarded-Server":"2caa236b7c38","X-Real-Ip":"93.73.59.123","X-Request-Id":"855cfd0a-2796-4bc1-a5a9-2c5e776bcdaa","X-Envoy-Expected-Rq-Timeout-Ms":"15000","X-Envoy-Original-Path":"/api/v2/barong/identity/sessions"}}',
        'source' => 'stdout',
        'severity' => 'WARN'
      }
    ]
    assert_equal(expected, filter(messages))
  end
end
