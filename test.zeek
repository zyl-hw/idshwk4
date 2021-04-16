event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="http_response", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="response404", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="http_UNIQUE_404_response", $apply=set(SumStats::UNIQUE));

    SumStats::create([$name="dns.requests.unique",
                      $epoch=10min,
                      $reducers=set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local R1 = result["http_response"];
                        local R2 = result["response404"];
                        local R3 = result["http_UNIQUE_404_response"];
                        if (R2$num > 2)
                        {
                            if((R2$num*1.0)/(R1$num*1.0) > 0.2)
                            {
                                if((R3$unique*1.0)/(R2$num*1.0)>0.5)
                                    print fmt("%s is a scanner with %.0f scan attemps on %d urls",key$host,R2$num,R3$unique);
                            }
                        }
                        }]);
    }


event http_reply(c:connection,version:string,code:count,reason:string)
{
    if (c$http$status_code == 404)
    {
        SumStats::observe("response404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
        SumStats::observe("http_UNIQUE_404_response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
    SumStats::observe("http_response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
}
