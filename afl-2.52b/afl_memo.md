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
