from eval.adversarial_review import review


def test_metamorphic_adversarial_review_stays_stable():
    assert review() == []
