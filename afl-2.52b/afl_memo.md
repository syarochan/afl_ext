### American Fuzzy Lopのソースコード解析
ここ最近のAmerican Fuzzy Lopに対してオレオレ実装した過程でソースコードを解析したので、その結果をブログにまとめてみようということで書いてみました。ソースコードの解析しているようなブログなどはとくにみたことがない(2018/03/19時点)ので書く価値があるのかなという自己満足で書いてみました<br>
<br>
### American Fuzzy Lopとは
American Fuzzy LopはGoogleのエンジニアである、Michal Zalewski氏らによるfuzzing toolである。fuzzingとはざっくりいうと「自動でバグ、脆弱性を見つけようぜ」というものである。<br>
<br>
有名なところで言うとCGC(Cyber Grand Challenge)でコンピュータ同士の攻防でfuzzingが使われていたりする。またここ最近の出来事としては2017年のプレスリリースされたMicrosoftの[Security Risk Detection](https://www.microsoft.com/en-us/security-risk-detection/)というものがある。これは[Neural fuzzing: applying DNN to software security testing](https://www.microsoft.com/en-us/research/blog/neural-fuzzing/)にかかれている通りfuzzingのアルゴリズムにDeep Neual Networkを適応させている。<br>
<br>
つまり、「自動でバグや脆弱性を見つけるサービスをはじめました」ということである。有名な企業がこういったことをやっているくらいホットな話題なので興味があるのであれば、ぜひこれをスタートアップとして、fuzzingに取り組んでほしい。<br>
<br>
### American Fuzzy Lopのアルゴリズムについて
Amrican Fuzzy Lopのアルゴリズムは遺伝的アルゴリズムである。もっと簡単に言うと「testするものが実行速度が速くて、カバー範囲(様々な条件分岐に対応している)が広くて、より深く(条件分岐の先の先)までtestすることができるのが良いcase」という考えのもとで実装がされている。<br>
<br>
American Fuzzy Lopとしては「とにかく速く、正確に、より多くの不要な部分（不要なライブラリでCPUを多く使うなど）を除き、シンプルなソースコードである」というのをコンセプトとしている。
<br>
### American Fuzzy Lopの変異戦略について
変異戦略とは、ユーザーが用意した初期値を様々な方法で変化させていく方法である。大きく分けて以下の6つある。<br>
- SIMPLE BITFLIP(xor戦略)<br>
- ARITHMETIC INC/DEC(数字加算/数字減算戦略)<br>
- INTERESTING VALUES(固定値を挿入する戦略)<br>
- DICTIONARY STUFF(辞書型のdataを挿入する戦略)<br>
- RANDOM HAVOC(ランダムに用意された戦略を選ぶ戦略)<br>
- SPLICING(dataをspliteする戦略)<br>
<br>
今回はこの6つのすべてをソースコード(afl-fuzz.cのfuzz_one関数)を用いながら詳しく説明していく。<br>
<br>
### 戦略に入る前処理(不要なdataのskip)
実際に戦略に入る前に最小限のfuzzingをするために不必要な部分のdata(queue)を取り除いていく。取り除かれるdataは以下の3つになる。<br>
- 戦略処理を待っているエラーを見つけるようなdata(pending_favored)があれば、そのdataがすでにfuzzingされているdata(already-fuzzed)または、エラーを起こすような変化がないdata(non-favored)であった場合は99％の確率で戦略を起こさずにreturnする。<br>
- penging_favoredがない場合は、fuzzingを実行するときのoptionでdumb_mode（ユーザーの初期値のみでfuzzingを行うmode,私の中ではアホの子modeとよんでいる）ではない、現在のdataがエラーを見つけるようなdata(favored queue)ではない、戦略処理を待っているqueueの数(queue_paths)が10個よりも少ない。という3つの条件が揃った時に以下の2つの条件にいく<br>
    - queue_pathsされているものを1周した時に加算される数(queue cycle)が1周より上、すでにfuzzingされているqueueの2つの条件があっていれば75％の確率で戦略を起こさずにreturnする。<br>
    - それ以外の条件であれば95%の確率で戦略を起こさずにreturnする。<br>
<br>
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
<br>
### 戦略に入る前処理(CALIBRATIONを失敗しているdataであるとき)
- CALIBRATIONとは、
### 戦略に入る前処理(dataの最小限までのtriming)
### 戦略に入る前処理(dataの点数付け)

### SIMPLE BITFLIP(xor戦略)<br>
### ARITHMETIC INC/DEC(数字加算/数字減算戦略)<br>
### INTERESTING VALUES(固定値を挿入する戦略)<br>
### DICTIONARY STUFF(辞書型のdataを挿入する戦略)<br>
### RANDOM HAVOC(ランダムに用意された戦略を選ぶ戦略)<br>
### SPLICING(dataをspliteする戦略)<br>
