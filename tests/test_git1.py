"""Проверки на настоящих локальных Git-репозиториях, без сети и bundle.

Запуск: python3 -m unittest discover -s tests -p 'test_git1.py' -v
"""
import asyncio
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('git1', Path(__file__).resolve().parents[1] / 'checks/GIT1.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def git(path, *args):
    return subprocess.run(['git', '-C', str(path), *args], check=True, text=True,
                          capture_output=True).stdout.strip()


def commit(path, message):
    git(path, '-c', 'user.name=Student', '-c', 'user.email=student@example.invalid',
        'commit', '--allow-empty', '-am', message)


class ExercisesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.base = Path(cls.fixture.name)
        seed = cls.base / 'source'
        seed.mkdir()
        git(seed, 'init', '--initial-branch=main')
        (seed / 'README.md').write_text('Учебная лаборатория\n')
        (seed / 'lab.conf').write_text('LAB_NAME="Учебная лаборатория"\nMAINTAINER="Не назначен"\n')
        git(seed, 'add', '.')
        commit(seed, 'Initial')
        cls.original = {k: getattr(lab, k) for k in ('SOURCE_ROOT', 'SOURCE_MAIN', 'SOURCE_TRAINING', 'TASK3_TREE')}
        lab.SOURCE_ROOT = git(seed, 'rev-parse', 'HEAD')
        (seed / 'services.txt').write_text('SSH\nGit\n')
        git(seed, 'add', '.')
        commit(seed, 'Services')
        lab.SOURCE_MAIN = git(seed, 'rev-parse', 'HEAD')
        git(seed, 'switch', '-c', 'training')
        conf = seed / 'lab.conf'
        conf.write_text(conf.read_text().replace('Учебная лаборатория', 'Тренировочная лаборатория'))
        commit(seed, 'Training')
        lab.SOURCE_TRAINING = git(seed, 'rev-parse', 'HEAD')
        git(seed, 'switch', 'main')
        conf.write_text(conf.read_text().replace('Не назначен', 'Учебная группа'))
        git(seed, 'add', 'lab.conf')
        lab.TASK3_TREE = git(seed, 'write-tree')
        commit(seed, 'Maintainer')
        cls.student_main = git(seed, 'rev-parse', 'HEAD')
        cls.template = cls.base / 'template'
        for node in lab.GIT_NODES:
            for task in lab.TASKS:
                path = cls.template / node / f'task-{task:02}'
                path.mkdir(parents=True)
                git(path, 'init', '--initial-branch=main')
                git(path, 'config', 'receive.denyCurrentBranch', 'updateInstead')
                main = cls.student_main if task in (3, 4) else lab.SOURCE_MAIN
                git(seed, 'push', str(path), f'{main}:refs/heads/main')
                if task == 5:
                    git(seed, 'push', str(path), 'training:training')
                    git(path, 'switch', 'training')

    @classmethod
    def tearDownClass(cls):
        for name, value in cls.original.items():
            setattr(lab, name, value)
        cls.fixture.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'nodes'
        shutil.copytree(self.template, self.root)
        self.addCleanup(self.tmp.cleanup)

    def path(self, task, node='Git1'):
        return self.root / node / f'task-{task:02}'

    def probe(self, task, path=None):
        return set(subprocess.run(['sh', '-c', lab.exercise_probe(task, str(path or self.path(task)))],
                                  check=True, capture_output=True, text=True).stdout.splitlines())

    def check(self, missing=()):
        root = self.root
        class Context:
            ostype = {n: 'linux' for n in lab.GIT_NODES if n not in missing}
            def __init__(self): self.scores, self.errors = {}, []
            async def run(self, node, command):
                command = command.replace('/root/task-', str(root / node / 'task-'))
                return subprocess.run(['sh', '-c', command], check=True, capture_output=True, text=True).stdout
            def add_check(self, name, score, maximum): self.scores[name] = (score, maximum)
            def error(self, message): self.errors.append(message)
        ctx = Context()
        asyncio.run(lab.check_repository(ctx))
        return ctx

    def test_all_five_tasks_on_three_nodes(self):
        ctx = self.check()
        self.assertFalse(ctx.errors)
        self.assertEqual(sum(s for s, _ in ctx.scores.values()), 77)
        self.assertEqual(sum(m for _, m in ctx.scores.values()), 77)

    def test_full_lab_includes_all_exercises_and_keeps_base_checks(self):
        root = self.root
        class Context:
            ostype = {n: 'linux' for n in lab.NODES}
            def __init__(self): self.scores, self.errors = {}, []
            async def run(self, node, cmd):
                if cmd == lab.HOSTNAME_CMD:
                    return f'{node}\n===\n{node}'
                if cmd == lab.GIT_CMD:
                    return 'GIT_INSTALLED'
                if cmd == lab.AUTH_KEYS_CMD:
                    return 'ssh-ed25519 TESTKEY'
                if node == lab.ROUTER:
                    for target in lab.GIT_NODES:
                        if cmd == lab.ssh_probe(target):
                            addr = lab.NODES[target][0][1].split('/')[0]
                            return f'hostname {addr}\nuser root\nKEY ssh-ed25519 TESTKEY'
                cmd = cmd.replace('/root/task-', str(root / node / 'task-'))
                return subprocess.run(['sh', '-c', cmd], check=True, capture_output=True, text=True).stdout
            def error(self, message): self.errors.append(message)
            def add_check(self, name, score, maximum): self.scores[name] = (score, maximum)
        ctx = Context()
        asyncio.run(lab.check(ctx))
        self.assertFalse(ctx.errors)
        self.assertEqual(sum(s for s, _ in ctx.scores.values()), 91)
        self.assertEqual(sum(m for _, m in ctx.scores.values()), 91)

    def test_repository_checks_do_not_change_files_or_git_metadata(self):
        def snapshot():
            return {p.relative_to(self.root): p.read_bytes()
                    for p in self.root.rglob('*') if p.is_file()}
        before = snapshot()
        self.check()
        self.assertEqual(before, snapshot())

    def test_task1_rejects_extra_commit(self):
        commit(self.path(1), 'Unrequested')
        self.assertNotIn('VERSION_OK', self.probe(1))
        self.assertIn('CLEAN_OK', self.probe(1))

    def test_task3_rejects_second_commit_and_other_file(self):
        path = self.path(3)
        commit(path, 'Extra')
        self.assertNotIn('VERSION_OK', self.probe(3))
        git(path, 'reset', '--hard', lab.SOURCE_MAIN)
        (path / 'services.txt').write_text('Changed\n')
        commit(path, 'Wrong change')
        self.assertNotIn('VERSION_OK', self.probe(3))

    def test_task4_requires_same_commit_not_only_same_files(self):
        path = self.path(4)
        git(path, 'reset', '--hard', lab.SOURCE_MAIN)
        conf = path / 'lab.conf'
        conf.write_text(conf.read_text().replace('Не назначен', 'Учебная группа'))
        commit(path, 'Recreated rather than copied')
        self.assertNotEqual(git(path, 'rev-parse', 'main'), self.student_main)
        ctx = self.check()
        self.assertEqual(ctx.scores['Задание 4: репозиторий /root/task-04'], (14, 15))
        self.assertEqual(ctx.scores['Задание 4: история совпадает во всех шести репозиториях'], (0, 1))

    def test_task3_commits_must_match_across_nodes(self):
        path = self.path(3)
        git(path, '-c', 'user.name=Student', '-c', 'user.email=student@example.invalid',
            'commit', '--amend', '-m', 'Different commit, same result')
        self.assertIn('VERSION_OK', self.probe(3))
        ctx = self.check()
        self.assertEqual(ctx.scores['Задание 3: один коммит на всех узлах'], (0, 1))

    def test_task5_requires_original_two_branches_and_training_checkout(self):
        path = self.path(5)
        git(path, 'switch', 'main')
        self.assertNotIn('BRANCHES_OK', self.probe(5))
        git(path, 'branch', '-D', 'training')
        self.assertNotIn('VERSION_OK', self.probe(5))

    def test_extra_branches_and_tags_rejected_remote_refs_allowed(self):
        path = self.path(1)
        git(path, 'update-ref', 'refs/remotes/origin/training', lab.SOURCE_MAIN)
        self.assertIn('BRANCHES_OK', self.probe(1))
        git(path, 'branch', 'extra')
        self.assertNotIn('BRANCHES_OK', self.probe(1))
        git(path, 'branch', '-D', 'extra')
        git(path, 'tag', 'extra')
        self.assertNotIn('BRANCHES_OK', self.probe(1))

    def test_dirty_worktree_index_and_untracked_files(self):
        path = self.path(2)
        (path / 'README.md').write_text('Changed\n')
        self.assertNotIn('CLEAN_OK', self.probe(2))
        git(path, 'add', 'README.md')
        self.assertNotIn('CLEAN_OK', self.probe(2))
        git(path, 'reset', '--hard', 'HEAD')
        (path / 'new.txt').write_text('Untracked\n')
        self.assertNotIn('CLEAN_OK', self.probe(2))

    def test_missing_nested_and_bare_repositories(self):
        self.assertNotIn('REPO_OK', self.probe(1, self.root / 'missing'))
        nested = self.path(1) / 'nested'
        nested.mkdir()
        self.assertNotIn('REPO_OK', self.probe(1, nested))
        bare = self.root / 'bare'
        git(self.root, 'init', '--bare', str(bare))
        self.assertNotIn('REPO_OK', self.probe(1, bare))

    def test_receive_setting_and_detached_head(self):
        path = self.path(2)
        git(path, 'config', '--unset', 'receive.denyCurrentBranch')
        self.assertNotIn('RECEIVE_OK', self.probe(2))
        git(path, 'switch', '--detach')
        self.assertNotIn('BRANCHES_OK', self.probe(2))

    def test_missing_node_does_not_pass_or_crash(self):
        ctx = self.check(missing=('Git3',))
        for task in lab.TASKS:
            self.assertEqual(ctx.scores[f'Задание {task}: репозиторий /root/task-{task:02}'], (10, 15))
        self.assertTrue(any('Git3' in e and 'не ответил' in e for e in ctx.errors))


if __name__ == '__main__':
    unittest.main()
