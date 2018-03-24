### American Fuzzy Lopのソースコード解析
ここ最近のAmerican Fuzzy Lopに対してオレオレ実装した過程でソースコードを解析したので、その結果をブログにまとめてみようということで書いてみました。ソースコードの解析しているようなブログなどはとくにみたことがない(2018/03/19時点)ので書く価値があるのかなという自己満足で書いてみました

### American Fuzzy Lopとは
American Fuzzy LopはGoogleのエンジニアである、Michal Zalewski氏らによるfuzzing toolである。fuzzingとはざっくりいうと「自動でバグ、脆弱性を見つけようぜ」というものである。<br>

有名なところで言うとCGC(Cyber Grand Challenge)でコンピュータ同士の攻防でfuzzingが使われていたりする。またここ最近の出来事としては2017年のプレスリリースされたMicrosoftの[Security Risk Detection](https://www.microsoft.com/en-us/security-risk-detection/)というものがある。これは[Neural fuzzing: applying DNN to software security testing](https://www.microsoft.com/en-us/research/blog/neural-fuzzing/)にかかれている通りfuzzingのアルゴリズムにDeep Neual Networkを適応させている。

つまり、「自動でバグや脆弱性を見つけるサービスをはじめました」ということである。有名な企業がこういったことをやっているくらいホットな話題なので興味があるのであれば、ぜひこれをスタートアップとして、fuzzingに取り組んでほしい。

### American Fuzzy Lopのアルゴリズムについて
Amrican Fuzzy Lopのアルゴリズムは遺伝的アルゴリズムである。もっと簡単に言うと「testするものが実行速度が速くて、カバー範囲(様々な条件分岐に対応している)が広くて、より深く(条件分岐の先の先)までtestすることができるのが良いcase」という考えのもとで実装がされている。<br>

American Fuzzy Lopとしては「とにかく速く、正確に、より多くの不要な部分（不要なライブラリでCPUを多く使うなど）を除き、シンプルなソースコードである」というのをコンセプトとしている。

### American Fuzzy Lopの変異戦略について
変異戦略とは、ユーザーが用意した初期値を様々な方法で変化させていく方法である。大きく分けて以下の6つある。<br>
- SIMPLE BITFLIP(xor戦略)<br>
- ARITHMETIC INC/DEC(数字加算/数字減算戦略)<br>
- INTERESTING VALUES(固定値を挿入する戦略)<br>
- DICTIONARY STUFF(辞書型のdataを挿入する戦略)<br>
- RANDOM HAVOC(ランダムに用意された戦略を選ぶ戦略)<br>
- SPLICING(dataをspliteする戦略)<br>

今回はこの6つのすべてをソースコード(afl-fuzz.cのfuzz_one関数)を用いながら詳しく、よりシンプルに説明をしていく。<br>

### 戦略に入る前処理(不要なdataのskip)
実際に戦略に入る前に最小限のfuzzingをするために不必要な部分のdata(queue)を取り除いていく。取り除かれるdataは以下の3つになる。<br>
- 戦略処理を待っているエラーを見つけるようなdata(pending_favored)があれば、そのdataがすでにfuzzingされているdata(already-fuzzed)または、エラーを起こすような変化がないdata(non-favored)であった場合は99％の確率で戦略を起こさずにreturnする。<br>
- penging_favoredがない場合は、fuzzingを実行するときのoptionでdumb_mode（ユーザーの初期値のみでfuzzingを行うmode,私の中ではアホの子modeとよんでいる）ではない、現在のdataがエラーを見つけるようなdata(favored queue)ではない、戦略処理を待っているqueueの数(queue_paths)が10個よりも少ない。という3つの条件が揃った時に以下の2つの条件にいく<br>
    - queue_pathsされているものを1周した時に加算される数(queue cycle)が1周より上、すでにfuzzingされているqueueの2つの条件があっていれば75％の確率で戦略を起こさずにreturnする。<br>
    - それ以外の条件であれば95%の確率で戦略を起こさずにreturnする。<br>

以下はそのソースコードに当たる部分である。<br>
```c
#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */
// already-fuzzed と non-favoredはskipする
    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {//pending_favoredがないときこちらの条件を比べる

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {//lower for never-fuzzed entries.

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;//75%の確率でreturn

    } else {//higher for already-fuzzed

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;//95%の確率でreturn

    }

  }

#endif /* ^IGNORE_FINDS */
```

### 戦略に入る前処理(CALIBRATIONを失敗しているdataであるとき)
- CALIBRATIONとは、実際にdata(queue)を使って実行ファイルを走らせ、そのqueueのカバー範囲、実行速度、どのようなエラーになるかなどを記録する関数である。<br>
- これからcalibrate_case関数の説明をしていく。<br>
- fuzz_one関数に入る前の段階でcalibration関数は実行されており、失敗するようなflag(cal_failed)が立つのは関数が実行され始めてすぐの部分である。<br>
- デフォルトの状態(dumb_modeではない状態)であればinit_forkserverを使って子プロセスを生成する。<br>
- write_to_testcaseで.cur_input fileにdataの内容を書き込む。<br>
- 書き込んだあと、run_target関数で子プロセスの方で実行ファイルをexecvで実行して、その実行結果を親プロセスに返す。<br>
- stageは全部で8回(fast calibrationのflagが立っていない時)行われる。つまり、run_targetは全部で8回行われる。<br>
- run_targetが終わるたびにカバー範囲(trace_bits)を使ってhashを生成する。<br>
- hashは一番最初にrun_targetを実行した時のhashを現在のqueueに保存したあとに、最初のカバー範囲をfirst_traceに入れて後のstageと比べる<br>
- 2回目以降に生成したhashが一番最初のhashと違っていた場合、新しいinputの組み合わせ(new tuple)で、新たなカバー範囲を見つけたので全体のカバー範囲(virgin_bits)の更新を行う<br>
- first traceとtrace bitsを比べていき、一致しなかったらその部分に変化があった場所(var_bytes)としてflagを立てる。<br>
- update_bitmap_score関数で現在のqueueが現時点で最も優れているqueue(top_rated)と比べて実行時間とdataの長さを掛けた数よりも小さかったらtop_ratedと入れ替える。<br>
- もしなかった場合はtop_ratedに現在のqueueを入れる。<br>
- queueに変化があった場所(var_bytes)があったというflagを立てる。<br>
以下に戦略に入る前処理(CALIBRATIONを失敗しているdataであるとき)を載せておく。cliburation関数の方は公開したコメント付きソースコードでみてほしい。<br>
```c
/*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {// 3より小さい場合のみcalibrate_case関数を実行

      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR)
        FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) {
      cur_skipped_paths++;// 現在のqueueをスキップしたのでスキップした数を増やす
      goto abandon_entry;
    }

  }
```
### 戦略に入る前処理(dataの最小限までのtrimming)
- trimとはdataの振る舞いに影響を与えない最小限のdataのtrimmingをおこなうものである。trim_case関数で行われる。これからtrim_case関数の説明をしていく。<br>
- trim_caseではdataを16で割り、1024まで2ずつ割っていく。このとき、run_target関数を実行して、hashが変わったかを比べて変わっていたらcalibration関数と同様にupdate_bitmap_scoreを更新するが、割り切れるまでループを抜けないので現在のtrace_bitsをclean_traceに保存する。<br>
- 割り切れる最小値まで割り続けるので必然的に「カバー範囲(trace_bits)に変化があった最小値の長さ」まで割られる。<br>
以下にtrimmingの部分のソースコードを載せておく。trim_caseの部分は公開したコメント付きソースコードを見てほしい<br>
```c
  /************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {

    u8 res = trim_case(argv, queue_cur, in_buf);// queueをtrimして実行させる

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;//放棄した数を増やす
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */
// 失敗していたとしてもtrim_done flagをたてる
    queue_cur->trim_done = 1;

    if (len != queue_cur->len) len = queue_cur->len;//trimmingしてqueueの長さが違っていたら変更する

  }

  memcpy(out_buf, in_buf, len);//trimされているのであればdataの更新を行う(trimされていなかったら値は変わっていない)
```
### 戦略に入る前処理(dataの点数付け)
- preformance scoreはqueueの点数付けを行う部分である。calculate_score関数で点数をつける。これからcalculate_score関数の説明をしていく。<br>
- scoreが良くなる条件は4つある。<br>
- 1つ目は平均実行時間よりも少なければ少ないほど良いscoreになる。<br>
- 2つ目はcover範囲が広ければ広いほど良いscoreになる。<br>
- 3つ目はqueue cycleの回数が高ければ高いほど良いscoreにする。これはqueueが多く実行されればされるほど変異を様々なtupleで行われエラーを見つけやすくなるためである。<br>
- 4つ目はより深く条件分の先の先(depth)までいくqueueは良いscoreになる。<br>
- calculate_scoreが終わって、変異戦略をskipする(正確にはRANDOM HAVOCまでgoto)条件として -d optionがある、すでにfuzzingされているもの(was_fuzzed)、過去にfuzzingした(resume)favored pathとしてqueue(passd_det)が残っている。(American Fuzzy Lopはoutputディレクトリに過去に中断したdata(queue)を記録しているため、それを使って再び途中から実行させることができる機能を持っている。このdataをresume queueという。20分以上実行した形跡があるのであればfuzzingを最初から実行させようとすると初期化の段階で警告文が出て実行が中断される)の3つの条件のうちどれかに当てはまるとskipする。<br>
- skipしなかった場合はこれから全部の戦略を実行しますflag(doing_det)を立てる。
以下はそのソースコードに当たる部分である。calculate_score関数は公開したコメント付きソースコードを見てほしい<br>
```c
  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);//queueのscoreをつける

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;//deterministic fuzzing flagを立てる
```
### SIMPLE BITFLIP(xor戦略)<br>
- SIMPLE BITFLIPでは、bit単位のxor、byte単位でのxorの2つの戦略でqueueを変異させていく。<br>
まずは、bit単位のxorの説明をしていく。
- bit単位のxorでは3つの段階にわけられてqueueを変異させていく。<br>
- 最初の段階では1byteを1つの部分に対して、0x80でstage数に合わせて右にbitシフトさせてxorをしていく。<br>
- 2段階目では1byteを2つの部分に対して、0x80でstage数に合わせて右にbitシフトさせてxorをしていく。<br>
- 3段階では1byteを4つの部分に対して、0x80でstage数に合わせて右にbitシフトさせてxorをしていく。<br>
基本的には処理は3つとも同じであるため、最初の段階のSingle walking bitだけを説明する。<br>
- stageごとに、common_fuzz_stuff関数が実行されてrun_target関数が実行される。run_targetの戻り値として返ってきた実行結果(fault)をsave_if_interesting関数を使って振り分ける。これからsave_if_interesting関数の説明をする。<br>
- save_if_interesting関数を開始してすぐに-C option(crash_mode)の場合の処理に入る。今回はデフォルトの処理の説明をこれからしていく。<br>
- switch文でFAULT_TMOUT、FAULT_CRASHでfaultの内容が振り分けられる。<br>
  - FAULT_TMOUTのとき、実行ファイルはtime outエラーを起こして終了している。<br>
    - time outを起こして終了した全体の数(total_tmouts)を加算する。<br>
    - simplify_trace関数を使ってtrace_bitsのnot hit、hit(それぞれ0x01、0x80でマークされている)のマークづけを行う。<br>
    - has_new_bitsを使って、trace_bitsとvirgin_tmout(time out error用の全体のカバー範囲)を比べて、見たことがないtime out(hit countの変更とnew tuple)がなければreturnをする<br>
    - unique time outの数を増やす(unique_tmouts)<br>
    - もし、ユーザーが設定したtime outが小さい場合はもう一度hang_tmout(1000ms)でrun_target関数を走らせる。<br>
    - FAULT_CRASHであればFAULT_CRASHの処理にいく。FAULT_TMOUTであれば何もしないでreturnする。<br>
  -  FAULT_CRASHのとき、実行ファイルはSEGVエラーを起こして終了している。<br>
    - 処理はFAULT_TMOUTと変わらないため省略
- (common_fuzz_stuff関数を抜けると)stageが8の倍数 - 1(8byte単位)とき、hashを生成して、それぞれの段階で自動辞書型(a_extras)の生成を行う<br>
  - 現在のstageが一番最後かつ、cksumとprev_cksum(前回のチェックサム)が一致するときは次の処理に入る。<br>
    - out_bufの一番最後の文字をa_collectに入れる。<br>
    - a_len(a_collectの長さ)の長さが3以上32以下であれば、maybe_add_auto関数を実行して自動辞書型(a_extras)の生成を行う<br>
  - cksumとprev_cksum(前回のチェックサム)が一致しないとき<br>
    - a_len(a_collectの長さ)の長さが3以上32以下であれば、maybe_add_auto関数を実行して自動辞書型(a_extras)の生成を行う<br>
    - prev_cksumをcksumに更新する。<br>
  - 現在のqueueのcksumと生成したcksumを比べて一致しなかった場合<br>
    - a_len(a_collectの長さ)の長さが32より下であれば、out_bufの一番最後の文字をa_collectに入れる。a_lenを加算する。<br>
- ループ処理を抜けるとSingle walking bitで見つけた、条件分岐先(queued_paths)、実行エラー(unique_crashes)を加算する。<br>
以下はそのソースコードに当たる部分である。save_if_interesting関数、simplify_trace関数、common_fuzz_stuff関数、maybe_add_auto関数、2段階目、3段階目は公開したコメント付きソースコードを見てほしい<br>
```c
  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 3;// len * 2^3した値(bit単位)をstage_maxにする
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;//実行してtime outとskip flagがあればgoto

    FLIP_BIT(out_buf, stage_cur);
       .
       .
       .

    if (!dumb_mode && (stage_cur & 7) == 7) {//stage_curが7の倍数であれば

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);//out_bufの1byteを追加最後のステージなのでa_lenの初期化はない

      } else if (cksum != prev_cksum) {//前回とチェックサムが違った場合

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len = 0;//addしたのでa_lenを初期化
        prev_cksum = cksum;//チェックサムの更新

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
        a_len++;

      }

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;//stage_flip1でみつけたpathとcrashesの数を加算
  stage_cycles[STAGE_FLIP1] += stage_max;//stageを実行した回数を加算
```
次にbyte単位のxorの説明をしていく。<br>
- byte単位でのxorでは1byte単位、2bytes単位、4bytes単位の3つでqueueを変異させていく。<br>
- 今回は1byte単位の説明だけをしていく。<br>
- ループに入ったすぐにout_bufの1byteを0xffで反転する。<br>
- common_fuzz_stuff関数でrun_target関数で実行ファイルを走らせる。<br>
- stageごとに変更を加えた場所にマーク付けを行う(eff_map)部分にマーク付けが行われていなかった場合<br>
  - dataの長さが128byte以上であればhashの生成を行う(ただし、dumb_modeでないとき)<br>
  - それ以外の時はqueueに保存されているチェックサムを反転させた値をcksumに入れる。<br>
  - cksumとqueueに保存されているチェックサムが違った場合eff_mapにマーク付けを行い、eff_mapにマーク付けされている数(eff_cnt)を増やす。<br>
- 反転させていたoutbufの1byteを元に戻す。<br>
- ループを抜けてすぐに、eff_mapにマーク付けされている数が90％以上あれば、lenを8byte単位にした状態でeff_mapの先頭からマーク付けを行う。<br>
- 8byteごとにマーク付けを行った数(blocks_eff_select)だけ加算する。<br>
- 全体の8byteごとにマーク付けを行った数(blocks_eff_total)を加算する<br>
1byte単位のxorの部分だけのソースコードを載せる。残りの部分は公開したソースコードで確認してほしい。<br>
```c
  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;//1byte反転させる

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)]) {//現在のstageがeff_mapになかった場合

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);// 現在のqueueの長さが128byte以上であったら
      else
        cksum = ~queue_cur->exec_cksum;//128byte以上ではない場合はチェックサムを反転させたものを生成

      if (cksum != queue_cur->exec_cksum) {//128byte以上で生成したチェックサム、反転させたqueueのチェックサムがqueueのチェックサムと違った場合、eff_mapに現在のstageのflagをつける
        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;
      }

    }

    out_buf[stage_cur] ^= 0xFF;//元に戻す

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */
//密集している数が90％より上であれば
  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {//lenの8byte単位の個数とlen AND 0x03の値(lenが1byteから7byte用)を足した値をeff_cntと比べるかつ、

    memset(eff_map, 1, EFF_ALEN(len));//8byte単位にアラインメントしたものをeff_mapの先頭から埋めていく

    blocks_eff_select += EFF_ALEN(len);//埋めた数だけ加算する

  } else {

    blocks_eff_select += eff_cnt;//それ以外であれば現在のeff_cntを加算する

  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;
```
### ARITHMETIC INC/DEC(数字加算/数字減算戦略)<br>
ここでの戦略では、1から35までの数字を順番に加算・減算をやっていく。<br>
- 加算と減算は8bit、16bit、32bitの3つの方法で行われる。<br>
- eff_mapにマーク付けがされていないところでは、この戦略は行わない。<br>
- 前回の戦略であるbitflipができなかったものに対して(could_be_bitflip関数を使って判断をする)、この戦略を行っていく。<br>
- できなかったものに対してやる理由は、前戦略でのbitflipと同じdataを実行しないようにするためである。<br>
- 16bit、32bitはlittle endianとbig endianを考慮した戦略になっている。<br>
今回は、16bitでの説明をしていく。<br>
- dataの長さが、2byteない状態であればARITHMETIC INC/DEC戦略をskipする。<br>
- stage_max(ループを行う最大回数)は加算、減算の2つのlittle endian用とbig endian用の4つ分を最大回数に設定をする。<br>
- out_bufを2byteずつorigに入れて、eff_mapに連続でマーク付けを行われているかを確認する。マークづけされていなければskipする。<br>
- マークされている場合、ARITHMETIC(1から35)までを順番にlittle endianとbig endianの加算と減算を行っていく。<br>
- 最初はlittle endian<br>
  - 加算するときにoverflowを起こしていないかをチェックしたあとに、could_be_bitflip関数を使ってbitflipができないことを確認する。これらの条件を突破したらcommon_fuzz_stuff関数を実行する。<br>
  - 減算するときにunderflowを起こしていないかをチェックしたあとに、could_be_bitflip関数を使ってbitflipができないことを確認する。これらの条件を突破したらcommon_fuzz_stuff関数を実行する<br>
- 次はbig endian<br>
  - 処理はlittle endianと変わらない。<br>
  - 変わるのはSWAP関数を使ってbig endianにするくらい。<br>
以下に、該当部分である16bitの戦略部分である。その他の部分は公開したソースコードを確認してほしい。<br>
```c
 if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;//4はINC/DECのlittle endianとBig endian用

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {
//SWAP16はlittle endian対策下位1byteと上位1byteを入れ替える(big endian用)
      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {//orig(2byte)を0xff(下位1byteがlittle endianなので上位にくる)と比べてoverflowしていないかチェックをする

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {//underflowチェックを行う下位1byteがjよりも小さかったら

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;//次はbig endianにして考える


      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

```
### INTERESTING VALUES(固定値を挿入する戦略)<br>
INTERESTING VALUESは、固定値を挿入するような戦略で、8bit,16bit,32bitの戦略で、それぞれの大きさでoverflow、underflow、off-by-one、比較するときにミスしそうな値を使ってfuzzingを行うようなものである。<br>
- 
### DICTIONARY STUFF(辞書型のdataを挿入する戦略)<br>
### RANDOM HAVOC(ランダムに用意された戦略を選ぶ戦略)<br>
### SPLICING(dataをspliteする戦略)<br>
