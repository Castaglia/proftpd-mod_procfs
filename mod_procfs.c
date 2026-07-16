/*
 * ProFTPD: mod_procfs -- a module for hiding the /proc filesystem
 * Copyright (c) 2026 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_procfs contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * -----DO NOT CHANGE THE LINES BELOW-----
 */

#include "conf.h"
#include "privs.h"

#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

#define MOD_PROCFS_VERSION	"mod_procfs/0.1"

module procfs_module;

static int procfs_engine = FALSE;
static int procfs_logfd = -1;
static pool *procfs_pool = NULL;

static int have_procfs = FALSE;

static const char *trace_channel = "procfs";

static int is_procfs_path(pool *p, const char *path) {
  int res = FALSE;
  char *abs_path;
  size_t abs_pathlen;

  abs_path = dir_abs_path(p, path, FALSE);
  abs_pathlen = strlen(abs_path);

  if (abs_pathlen >= 6 &&
      strncmp(abs_path, "/proc/", 6) == 0) {
    res = TRUE;

  } else if (abs_pathlen == 5 &&
             strcmp(abs_path, "/proc") == 0) {
    res = TRUE;
  }

  return res;
}

/* Configuration handlers
 */

/* usage: ProcfsEngine on|off */
MODRET set_procfsengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1); 
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: ProcfsLog path|"none" */ 
MODRET set_procfslog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1); 
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
 
  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }
 
  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET procfs_pre_rnfr(cmd_rec *cmd) {
  const char *path;

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (cmd->argc < 2) {
    return PR_DECLINED(cmd);
  }

  /* TODO: Add similar decoding, handling of spaces as done by mod_core. */

  path = cmd->arg;
  if (is_procfs_path(cmd->tmp_pool, path) == TRUE) {
    pr_log_pri(PR_LOG_NOTICE, "%s %s denied by mod_procfs",
      (char *) cmd->argv[0], path);
    pr_response_add_err(R_550, _("%s: %s"), cmd->arg, strerror(ENOENT));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  return PR_DECLINED(cmd);
}

MODRET procfs_post_pass(cmd_rec *cmd) {
  config_rec *c;

  if (have_procfs == FALSE) {
    procfs_engine = FALSE;
    return PR_DECLINED(cmd);
  }

  c = find_config(main_server->conf, CONF_PARAM, "ProcfsEngine", FALSE);
  if (c != NULL) {
    procfs_engine = *((int *) c->argv[0]);
  }

  if (procfs_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Check whether we are chrooted.  If so, then we need not do anything. */
  if (session.chroot_path != NULL) {
    if (strcmp(session.chroot_path, "/") != 0) {
      pr_trace_msg(trace_channel, 3,
        "session is chrooted to '%s', disabling mod_procfs",
        session.chroot_path);
      procfs_engine = FALSE;
    }
  }

  return PR_DECLINED(cmd);
}

/* Event Listeners
 */

#if defined(PR_SHARED_MODULE)
static void procfs_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_procfs.c", (const char *) event_data) != 0) {
    return;
  }

  pr_event_unregister(&procfs_module, NULL, NULL);

  (void) close(procfs_logfd);
  procfs_logfd = -1;

  if (procfs_pool != NULL) {
    destroy_pool(procfs_pool);
    procfs_pool = NULL;
  }
}
#endif /* PR_SHARED_MODULE */

static void procfs_restart_ev(const void *event_data, void *user_data) {
  (void) close(procfs_logfd);
  procfs_logfd = -1;

  if (procfs_pool != NULL) {
    destroy_pool(procfs_pool);
  }

  procfs_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(procfs_pool, MOD_PROCFS_VERSION);
}

/* Initialization functions
 */

static int procfs_init(void) {
  struct stat st;

  if (procfs_pool != NULL) {
    destroy_pool(procfs_pool);
  }

  procfs_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(procfs_pool, MOD_PROCFS_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&procfs_module, "core.module-unload", procfs_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&procfs_module, "core.restart", procfs_restart_ev, NULL);

  /* Check for the presence of the /proc filesystem on this host.  If it
   * is not present, then we need do nothing else.
   */
  if (lstat("/proc/", &st) == 0) {
    pr_log_debug(DEBUG10, MOD_PROCFS_VERSION ": found /proc/ filesystem");

    if (S_ISDIR(st.st_mode)) {
      have_procfs = TRUE;

      /* TODO: Automatically set ProcfsEngine on in such cases? */

    } else {
      pr_log_debug(DEBUG10, MOD_PROCFS_VERSION ": /proc/ is not a directory");
    }

  } else {
    pr_log_debug(DEBUG5, MOD_PROCFS_VERSION
      ": did not find /proc filesystem: %s", strerror(errno));
  }

  return 0;
}

static int procfs_sess_init(void) {
  config_rec *c;
  const char *path;
  int res, xerrno;

  c = find_config(main_server->conf, CONF_PARAM, "VRootLog", FALSE);
  if (c == NULL) {
    return 0;
  }

  path = c->argv[0];
  if (strcasecmp(path, "none") == 0) {
    return 0;
  }

  PRIVS_ROOT
  res = pr_log_openfile(path, &procfs_logfd, 0660);
  xerrno = errno;
  PRIVS_RELINQUISH

  switch (res) {
    case 0:
      break;

    case -1:
      pr_log_debug(DEBUG1, MOD_PROCFS_VERSION
        ": unable to open ProcfsLog '%s': %s", path, strerror(xerrno));
      break;

    case PR_LOG_SYMLINK:
      pr_log_debug(DEBUG1, MOD_PROCFS_VERSION
        ": unable to open ProcfsLog '%s': %s", path, "is a symlink");
      break;

    case PR_LOG_WRITABLE_DIR:
      pr_log_debug(DEBUG1, MOD_PROCFS_VERSION
        ": unable to open ProcfsLog '%s': %s", path,
        "parent directory is world-writable");
      break;
  }

  return 0;
}

/* Module API tables
 */

static conftable procfs_conftab[] = {
  { "ProcfsEngine",	set_procfsengine,	NULL },
  { "ProcfsLog",	set_procfslog,		NULL },
  { NULL }
};

static cmdtable procfs_cmdtab[] = {
  { PRE_CMD,		C_RNFR,	G_NONE,	procfs_pre_rnfr,	FALSE, FALSE },

  { POST_CMD,		C_PASS, G_NONE, procfs_post_pass,	FALSE, FALSE },
  { 0, NULL }
};

module procfs_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "procfs",

  /* Module configuration handler table */
  procfs_conftab,

  /* Module command handler table */
  procfs_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  procfs_init,

  /* Session initialization function */
  procfs_sess_init,

  /* Module version */
  MOD_PROCFS_VERSION
};
