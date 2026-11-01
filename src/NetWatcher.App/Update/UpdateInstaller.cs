using System.Diagnostics;
using NetWatcher.Core.Update;

namespace NetWatcher.App.Update;

public static class UpdateInstaller
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly string[] Documents = ["README.md", "THIRD-PARTY-NOTICES.md"];

    // Call from the UI thread so that shutdown runs on its original synchronization context.
    // The package is consumed and disposed on both success and failure.
    public static async Task InstallAndRestartAsync(PreparedUpdate update, Action shutdown,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        ArgumentNullException.ThrowIfNull(shutdown);
        var entered = false;
        var cleaned = false;
        Transaction? transaction = null;
        try
        {
            await Gate.WaitAsync(cancellationToken);
            entered = true;
            transaction = await Task.Run(() => Install(update, cancellationToken), cancellationToken);
            await Task.Run(update.Dispose);
            cleaned = true;
            shutdown();
        }
        catch (Exception ex)
        {
            Exception? rollbackError = null;
            if (transaction != null)
            {
                try { await Task.Run(transaction.Rollback); }
                catch (Exception rollback) { rollbackError = rollback; }
            }
            if (rollbackError != null)
                throw new UpdateException("Не удалось завершить обновление и восстановить файлы. Резервная копия: " +
                    transaction!.BackupPath + ". " + rollbackError.Message, new AggregateException(ex, rollbackError));
            if (ex is OperationCanceledException)
                throw;
            throw new UpdateException("Не удалось установить обновление: " + ex.Message, ex);
        }
        finally
        {
            transaction?.Process?.Dispose();
            if (!cleaned) await Task.Run(update.Dispose);
            if (entered) Gate.Release();
        }
    }

    private static Transaction Install(PreparedUpdate update, CancellationToken token)
    {
        var path = Environment.ProcessPath ?? throw new UpdateException("Не удалось определить путь NetWatcher.exe.");
        if (!string.Equals(Path.GetFileName(path), "NetWatcher.exe", StringComparison.OrdinalIgnoreCase))
            throw new UpdateException("Обновление доступно при запуске NetWatcher.exe.");
        var transaction = new Transaction(path);
        try
        {
            token.ThrowIfCancellationRequested();
            if (!File.Exists(update.ExecutablePath))
                throw new UpdateException("Подготовленный файл NetWatcher.exe не найден.");
            // Copy first: an interrupted cross-volume copy must never become the installed exe.
            File.Copy(update.ExecutablePath, transaction.IncomingPath, false);
            foreach (var name in Documents)
            {
                if (!File.Exists(Path.Combine(update.DirectoryPath, name)))
                    continue;
                var target = Path.Combine(transaction.InstallDirectory, name);
                var backup = File.Exists(target) ? File.ReadAllBytes(target) : null;
                transaction.Documents.Add((target, backup));
            }
            token.ThrowIfCancellationRequested();
            // A previous successful update may have left a locked backup. Fail before replacing anything.
            if (File.Exists(transaction.BackupPath))
                File.Delete(transaction.BackupPath);
            File.Move(path, transaction.BackupPath);
            transaction.OriginalMoved = true;
            File.Move(transaction.IncomingPath, path);
            foreach (var (target, _) in transaction.Documents)
            {
                token.ThrowIfCancellationRequested();
                transaction.ModifiedDocuments.Add(target);
                File.Copy(Path.Combine(update.DirectoryPath, Path.GetFileName(target)), target, true);
            }
            token.ThrowIfCancellationRequested();
            transaction.Process = Process.Start(new ProcessStartInfo(path)
            {
                UseShellExecute = true,
                WorkingDirectory = transaction.InstallDirectory,
                Arguments = "--after-update"
            }) ?? throw new UpdateException("Не удалось запустить новую версию.");
            return transaction;
        }
        catch (Exception ex)
        {
            try { transaction.Rollback(); }
            catch (Exception rollback)
            {
                throw new UpdateException("Не удалось восстановить файлы. Резервная копия: " +
                    transaction.BackupPath + ". " + rollback.Message, new AggregateException(ex, rollback));
            }
            throw;
        }
        finally
        {
            try { File.Delete(transaction.IncomingPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private sealed class Transaction(string executablePath)
    {
        public string InstallDirectory { get; } = Path.GetDirectoryName(executablePath)!;
        public string BackupPath { get; } = executablePath + ".old";
        public string IncomingPath { get; } = executablePath + ".update-" + Guid.NewGuid().ToString("N");
        public bool OriginalMoved { get; set; }
        public Process? Process { get; set; }
        public List<(string Target, byte[]? Backup)> Documents { get; } = [];
        public HashSet<string> ModifiedDocuments { get; } = [];

        public void Rollback()
        {
            var errors = new List<Exception>();
            if (Process != null)
            {
                try
                {
                    if (!Process.HasExited)
                    {
                        Process.Kill();
                        if (!Process.WaitForExit(5000))
                            throw new IOException("Новая версия ещё работает.");
                    }
                }
                catch (Exception ex) { errors.Add(ex); }
            }
            if (OriginalMoved)
            {
                try
                {
                    File.Move(BackupPath, executablePath, true);
                    OriginalMoved = false;
                }
                catch (Exception ex) { errors.Add(ex); }
            }
            foreach (var (target, backup) in Documents.Where(d => ModifiedDocuments.Contains(d.Target)))
            {
                try
                {
                    if (backup != null) File.WriteAllBytes(target, backup);
                    else File.Delete(target);
                }
                catch (Exception ex) { errors.Add(ex); }
            }
            // Preserve document backups if rollback itself failed.
            if (errors.Count != 0)
            {
                foreach (var (target, backup) in Documents.Where(d => d.Backup != null))
                {
                    try { File.WriteAllBytes(target + ".backup", backup!); }
                    catch (Exception ex) { errors.Add(ex); }
                }
                throw new AggregateException("Откат обновления не завершён. Копии документов: " + InstallDirectory, errors);
            }
        }
    }
}
