import 'package:cryppo/rsa/signature.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('can load serialised string', () {
    final serialised =
        'Sign.Rsa4096.p0qcl-UInJDr9iDbDKbhoMy4skstHep4oiqnB-oYOeDyPv1elN7vN1QTr1gs_0KValXCP1mpWIy9IdPAU1LkRM38_fA4yhizsSuR_BCEWuc7-AP6kAo42DrkyKJUeMZ6zFBBEluWNktHpjcRefKBSKUseMo1nJC9kxxQFBgC0Z9zwYVuEbM4scP59T5L06NS3FwWV2H2vPQCfx1_ipgZis-EPLvr0Qzy9XygsRd0IrTEBgaeyjazgzUtmYxPlSmMo91tVhxf4802cVi1SVDSBnibY-WOhRLWOwveT4f07674oiwhFUJO7w2VuVBJBJq6foWf6WHnEn1KVFCsx_wqmmR3nH3v7nf145qHZYoMf64mRdLxH6SCWYi4qWvUE1XdawnLXlyk2dCsFP8GQkW4ZZZGQ8plVS9e0OU_-S48AMDKOQcYP8RBy2rbZALMeoe4YUoeaAf03iY17DIcG63kPjps1oKoIXZdDfQ6Ycf8aii9Hw9k3pin1TtxnkGsxSYs9fsvERLvL8FlgzX-REoR-sXuNrKmwDXsHrPpCqk9ZPSGGDyRPcdDKMSuVo1WtnckA6TuGIWsFEL3GFRV9RQ9aiG4HfTUD5A-qmJlrjCu6PzWxEI_eKxZcQUfC86uXumXOxJpSqD4QOzxJgKukF-YN-JXEo2C0a_4l_128pB7EYc=.QnJlYWRlZCBmcmllZCBjaGlja2VuIHdpdGggd2FmZmxlcy4gU2VydmVkIHdpdGggbWFwbGUgc3lydXAu';
    final sig = Signature.fromSerializedString(serialised);
    expect(sig.keySize, 4096);
    expect(sig.data.length, 60);
    expect(sig.signature.length, 512);
  });

  test('use base64 url encoding or throws error', () {
    final nonBase64UrlString =
        'Sign.Rsa4096.Hxsm+t4duurAuBC9ympzxBAAmd0V9q2NIFVw6TEE7aLBQktQCQK1XE9Dz/WGWFP2w0h5LpAOJNTR0V7YzuHa9SYliZBc0frQIAJZHy7H4wpTiLP+Wx0gdl4GSTfu5hr/qnDsNuL1O41JG9KqEQllpfVNCpzGocICDRLP873UytYrCAq4sPyf8VlwMGj/rf90GXeWJ7N0VfMWTwbBLK1zYYfVqQtyhAMvjh38VDt1l1a5JfkB3mkmI3m7m1xfJ653RssJiPGuGR+YtBj+avn9cUpl9SGk/e3m8lDxtF5cZcnNBSxrdUN//obFy+RNEwNuJdv447jU2nzZucyRMOgDjuzGXxXe0JC0VQbQoRBfxMIEZZmi34ezm8bae4u7WjJg45ehR/kCDjzGRfsXQdeLY5STZ+444Ve/mi4EumaesYYLklxH1uxh2LPRzy5pb3Olupvcf/Lt4E6Ou2kzzluzUiIPKBO9hfZ3/YAy7rOnM5R/ZqpYl3BICXoSPkEBa4uCU7RghDR0l972T/A+oVEFNuluV2VqhKPu21qmnSVJbDRKCkxHMo+r+BQy89R3vGB6kl8h0UuizFnHJ1n80HxbteJaEH8B0HOWP6KQVXPqMlGQ1o9yze35Tc7w1SIeSRwEjIXgAV8SEjNAql5gftwyV4t1JP5FIYTA6hK63LnoEFI=.SGVsbG8gV29ybGQ=';
    expect(() => Signature.fromSerializedString(nonBase64UrlString),
        throwsException);
  });
}
