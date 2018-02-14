### AFLについて
## README.txt
- QEMUのサポート(userspaceでのBlackBox fuzzing)はしているが、2-5倍までパフォーマンスが落ちる。
- dynamic linkよりもstatic linkでやらなければいけない。
- libdislocatorライブラリを使うとheapのメモリアクセス違反の簡易的な検知ができる。
- AFL_PRELOADを使ってロードさせる(詳細はREADME.dislocator)
- ./afl-fuzz -i- -o existing_output_dir [...etc...]のようにすると途中でやめた時の結果を用いて実行する。
- 辞書型の初期値はあり、ユーザーも作成できるがかなり難しい。bestのものが作れたとしてもその実行ファイル専用のものになる。(http://lcamtuf.blogspot.com/2015/01/afl-fuzz-making-up-grammar-with.html)
- -xオプションで辞書型の初期値を使える。
- 辞書型を作成するときは2-16bytesの間がsweet spots
- SQliteの簡単なバグの見つけ方（http://lcamtuf.blogspot.com/2015/04/finding-bugs-in-sqlite-easy-way.html）
- tokencapをつかって余計なsyntax tokensを辞書型を使って通すことができる。ただし、linuxだけ(詳細はREADME.tokencap)
- -Cオプションでcrash exploration modeでどのような探索をしてクラッシュを起こしたのかを表示してくれる。
- fuzzing対象に合わせてcrash内容をabortした時にtraceしてくれる。
- FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION, __AFL_COMPILERのどちらかでsanity checkを簡易的に行ってくれる
- diskの書き込みを頻繁に行うため、iostat -d 3 -x -k [...optional disk ID...]で確認できる。
- 13)の部分結構重要(64bit向けの考え方、UIの変更するツール、ネットワーク検証ツール、人が読めるようなcodeにするツール)

# perf_tips.txt
- 1KB以下のtest caseを作成しなければならない。1KBまでなら71%の確率でバグを見つけることができる。
- 1KBを超えるとバグを見つける確率は11%までになり、10KBを超えると1%までになる。
- LLVM-based instrumentation modeを使えば2倍くらい早くなる。しかし、clangだけ。GCCでは動かない。(詳細はllvm_mode/README)
- fork serverを使うようなプログラムではスタートアップ時に大きな恩恵を受ける。（詳しくは/README.llvm_modeのBonus feature #1: deferred instrumentation）
- trace PC modeでは、普通のafl-clang-fastに比べて20％遅くなる。afl-clangでは5％ほど遅くなる。遅くなる理由としてはinlineではないから。
- CPUのコア数に応じて並列処理をさせることができる。(詳細はparallel_fuzzing.txt)
- 並列処理はマルチコア、マルチシステムに対応している。マルチシステムにはSSHを使ってつなげる。
- client-server型のfuzzingをすることもできる。しかし、インタネット上、信用できないユーザーに使わせるのは危険(RCEされるため)
- -M(master)はデータを反映させる場所、-S(Secondary)は子プロセスデータを解析させる場所
- status確認はscriptを走らせている（詳細はafl-whatsup）
- -mオプションを使ってメモリに制限をかけて余計なことにCPUを使わないようにする。LIMIT_MBを使って設定することもできる。(README.txt)
- -tオプションでlimitを5くらいまでに減らして速く実行することができる。
- fuzzing speedをOSレベルから変更することができる。(詳細は8 Check OS configuration)
- -dオプションをつけることで大きい入力処理、深くまで探索することがなくなる。
- -fオプションは入力で変異した内容をファイルに書き込む。
- -nオプションはblind fuzzer mode

## technical_details.txt
- tupleがどのようにキューに生成されるかはいかのようになる。
  1) つぎのtupleが存在しない場合動くようにセットする
  2) 勝ったtuple（遺伝的アルゴリズムで）がキューに入る
  3) 全てのtupleが入ったら動くようにセットする
  4) もしなくなったらまた1に戻る
- queueに入っているものがどのように取り出されるかは以下のようになる。
- まだfuzzingされていなものがqueueの中に存在していたらfuzzingしたものは99％無視してまだfuzzingされていなもの取り出す
  - fuzzingされていないものが存在しなかったら
    - 現在のすでにfuzzingされものをエントリーする前に95％ほどスキップする
    - いくつかのfuzzingをためさずに75％ほど削る

- afl-tminはまず最初にnon-instruction modeでシンプルにターゲットをcrashしにいく。それでもcrashできなかったら、instruction modeで全く同じpathでcrashしにいく。 以下はそのアルゴリズムである。
1) 大きいブロックサイズの0x00のものを用意して数をへらしながら実行する
2) ブロックサイズを減らして実行する
3) アルファベットの文字と0x00を組み合わせながら配置を変えつつ実行する
4) 0x00以外のもので実行する

- fuzzingの戦略として、ランダムなのもので実行する前にsequential bit flipsとsimple arithmeticsを行う。様々な種類がある（詳しくはhttps://lcamtuf.blogspot.jp/2014/08/binary-fuzzing-strategies-what-works.html）以下のような順番でやっていったあとに最後にユーザーの初期値を使うユーザーの初期値で新たなpathsが見つかる可能性はだいたい20％くらい(ここまで全てのステップを実行したあとでの確率)
Walking bit flips: 
Walking byte flips: 
Simple arithmetics: 
Known integers: 
Stacked tweaks:
    Single-bit flips,
    Attempts to set "interesting" bytes, words, or dwords (both endians),
    Addition or subtraction of small integers to bytes, words, or dwords (both endians),
    Completely random single-byte sets,
    Block deletion,
    Block duplication via overwrite or insertion,
    Block memset. 
the block size for block operations is capped at around 1 kB.
- de-duplication crashesはエラーの内容を深く掘り下げていくことであるAFLは以下の2つのように処理する。
 - 今まで見たことのないようなtupleのエラー内容であること
 - 早い段階でfaultsをおこすようなものであること
- crash exploration modeというものがある(http://lcamtuf.blogspot.com/2014/11/afl-fuzz-crash-exploration-mode.html)
- crash exploration modeは-Cオプションで使うことができるcrashesのtraceオプションである。
- 自動で実行されるようになっており、crash pointまで実行される。
- execveを一回一回変異inputsのために実行させるのライブラリの初期化のコストがかかるためよろしくないからfork-serverを作った。(https://lcamtuf.blogspot.jp/2014/10/fuzzing-binaries-without-execve.html)
- deferred modeはuser inputsが大きい物はスキップするようなmode。10倍くらいまで速くなる。
- persistent modeはocerheadになりそうなforkに制限をかけるもの。
- QEMUを使うとき、fork-serverはQEMUとparent processの間にAFL fork serverがある。

## historicak_notes
# AFLに関する考え方、戦略に対するコスト
- AFLは以下の考えで実装が行われている
- スピードが大切である。その上でトリミングの構文分析の正確性、不必要な関数の部分、input fileに対するトリミングの排除を目指す。
- 確実性が大切である。戦略に沿って行っていく。（symbolic実行はゴミという考え）
- simple is bestである。一人でもツールの使い方がわかるように工夫をしている。(ツールを理解するのに時間を多く割かなくて良い)
- つながっていることが大切である。一般的にリソースがすくなかったり、余計にCPUをつかったりするけどAFLはそんなことはしない。


