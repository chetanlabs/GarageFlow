-- =============================================================================
-- GarageFlow — Additive Superadmin & Owner Provisioning Migration (Non-Destructive)
-- =============================================================================
-- Preserves all 12 existing GarageFlow tables, columns, foreign keys, views,
-- triggers, RPCs, and Row Level Security (RLS) policies without modification.
--
-- PREREQUISITE:
--   1. Existing GarageFlow Phase 1-5 schema (or a fresh Supabase project).
--   2. Provision the temporary Superadmin user in Supabase Dashboard:
--      Authentication -> Users -> Add user -> Create new user:
--        Email: superadmin@example.com
--        Password: SuperAdmin@123 (auto-confirm user enabled for dev/testing)
--      Then run the final INSERT block below (replacing or matching email) to
--      grant trusted Superadmin role in public.superadmin_accounts.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. Trusted Superadmin Accounts Table
--    Authoritative server-side role table. Frontend NEVER trusts selected UI role.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.superadmin_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL DEFAULT 'Superadmin',
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.superadmin_accounts ENABLE ROW LEVEL SECURITY;

-- Drop only our own new policies if re-running idempotently
DROP POLICY IF EXISTS superadmin_self_read ON public.superadmin_accounts;

-- Authenticated users can only inspect their own active Superadmin record.
-- Insert/Update/Delete are intentionally denied to authenticated & anon roles
-- (must be managed by service_role / Supabase SQL Editor).
CREATE POLICY superadmin_self_read
  ON public.superadmin_accounts
  FOR SELECT
  TO authenticated
  USING (auth_user_id = auth.uid() AND is_active = true);

REVOKE ALL ON public.superadmin_accounts FROM anon, authenticated;
GRANT SELECT ON public.superadmin_accounts TO authenticated;

-- -----------------------------------------------------------------------------
-- 2. Trusted Superadmin Check Helper & Role Verification RPC
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.is_active_superadmin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.superadmin_accounts sa
    WHERE sa.auth_user_id = auth.uid()
      AND sa.is_active = true
  );
$$;

REVOKE ALL ON FUNCTION public.is_active_superadmin() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_active_superadmin() TO authenticated;

CREATE OR REPLACE FUNCTION public.verify_superadmin_role()
RETURNS TABLE (
  is_superadmin BOOLEAN,
  full_name TEXT,
  email TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  v_rec public.superadmin_accounts%ROWTYPE;
BEGIN
  IF auth.uid() IS NULL THEN
    RETURN QUERY SELECT false, NULL::TEXT, NULL::TEXT;
    RETURN;
  END IF;

  SELECT *
    INTO v_rec
    FROM public.superadmin_accounts sa
   WHERE sa.auth_user_id = auth.uid()
     AND sa.is_active = true
   LIMIT 1;

  IF FOUND THEN
    RETURN QUERY SELECT true, v_rec.full_name, v_rec.email;
  ELSE
    RETURN QUERY SELECT false, NULL::TEXT, NULL::TEXT;
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.verify_superadmin_role() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.verify_superadmin_role() TO authenticated;

-- -----------------------------------------------------------------------------
-- 3. Garage Owner Accounts Table (Managed Exclusively by Superadmin)
--    Tracks Owner Name, Garage Name, Owner Gmail, and setup/active status.
--    Links to auth.users once the owner completes email invitation/setup.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.garage_owner_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_name TEXT NOT NULL CHECK (char_length(trim(owner_name)) >= 2),
  garage_name TEXT NOT NULL CHECK (char_length(trim(garage_name)) >= 2),
  owner_email TEXT NOT NULL UNIQUE CHECK (owner_email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  auth_user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'Setup Pending'
    CHECK (status IN ('Setup Pending', 'Active', 'Suspended')),
  invited_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_at TIMESTAMPTZ,
  created_by_superadmin_id UUID REFERENCES public.superadmin_accounts(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_garage_owner_accounts_email
  ON public.garage_owner_accounts (lower(owner_email));
CREATE INDEX IF NOT EXISTS idx_garage_owner_accounts_status
  ON public.garage_owner_accounts (status);

ALTER TABLE public.garage_owner_accounts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS superadmin_manage_garage_owners ON public.garage_owner_accounts;
DROP POLICY IF EXISTS owner_read_own_account ON public.garage_owner_accounts;

-- Only active Superadmins can view, create, or update Garage Owner accounts
CREATE POLICY superadmin_manage_garage_owners
  ON public.garage_owner_accounts
  FOR ALL
  TO authenticated
  USING (public.is_active_superadmin())
  WITH CHECK (public.is_active_superadmin());

-- Garage Owners can read only their own linked record
CREATE POLICY owner_read_own_account
  ON public.garage_owner_accounts
  FOR SELECT
  TO authenticated
  USING (auth_user_id = auth.uid());

REVOKE ALL ON public.garage_owner_accounts FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.garage_owner_accounts TO authenticated;

-- -----------------------------------------------------------------------------
-- 4. Superadmin Platform Settings Table
--    Stores GarageFlow's shared Meta WhatsApp App configuration & Superadmin
--    system notification preferences (strictly separate from per-garage settings).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.superadmin_platform_settings (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  meta_app_id TEXT NOT NULL DEFAULT '',
  meta_waba_id TEXT NOT NULL DEFAULT '',
  meta_webhook_url TEXT NOT NULL DEFAULT '',
  whatsapp_api_status TEXT NOT NULL DEFAULT 'Configuration Required'
    CHECK (whatsapp_api_status IN ('Configuration Required', 'Connected', 'Error')),
  notify_new_owner_created BOOLEAN NOT NULL DEFAULT true,
  notify_owner_activated BOOLEAN NOT NULL DEFAULT true,
  notify_system_health_alerts BOOLEAN NOT NULL DEFAULT true,
  notify_whatsapp_api_errors BOOLEAN NOT NULL DEFAULT true,
  updated_by_auth_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO public.superadmin_platform_settings (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;

ALTER TABLE public.superadmin_platform_settings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS superadmin_manage_platform_settings ON public.superadmin_platform_settings;

CREATE POLICY superadmin_manage_platform_settings
  ON public.superadmin_platform_settings
  FOR ALL
  TO authenticated
  USING (public.is_active_superadmin())
  WITH CHECK (public.is_active_superadmin());

REVOKE ALL ON public.superadmin_platform_settings FROM anon, authenticated;
GRANT SELECT, UPDATE ON public.superadmin_platform_settings TO authenticated;

-- -----------------------------------------------------------------------------
-- 5. Superadmin Owner Provisioning & Listing RPCs
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.superadmin_create_garage_owner(
  p_owner_name TEXT,
  p_garage_name TEXT,
  p_owner_email TEXT
)
RETURNS public.garage_owner_accounts
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  v_sa_id UUID;
  v_clean_owner TEXT := trim(COALESCE(p_owner_name, ''));
  v_clean_garage TEXT := trim(COALESCE(p_garage_name, ''));
  v_clean_email TEXT := lower(trim(COALESCE(p_owner_email, '')));
  v_inserted public.garage_owner_accounts%ROWTYPE;
BEGIN
  SELECT sa.id
    INTO v_sa_id
    FROM public.superadmin_accounts sa
   WHERE sa.auth_user_id = auth.uid()
     AND sa.is_active = true
   LIMIT 1;

  IF v_sa_id IS NULL THEN
    RAISE EXCEPTION 'Unauthorized: Active Superadmin role required.'
      USING ERRCODE = '42501';
  END IF;

  IF char_length(v_clean_owner) < 2 THEN
    RAISE EXCEPTION 'Owner Name must be at least 2 characters.';
  END IF;

  IF char_length(v_clean_garage) < 2 THEN
    RAISE EXCEPTION 'Garage Name must be at least 2 characters.';
  END IF;

  IF v_clean_email !~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' THEN
    RAISE EXCEPTION 'Please provide a valid Owner Gmail address.';
  END IF;

  INSERT INTO public.garage_owner_accounts (
    owner_name,
    garage_name,
    owner_email,
    status,
    invited_at,
    created_by_superadmin_id
  )
  VALUES (
    v_clean_owner,
    v_clean_garage,
    v_clean_email,
    'Setup Pending',
    now(),
    v_sa_id
  )
  RETURNING * INTO v_inserted;

  RETURN v_inserted;
END;
$$;

REVOKE ALL ON FUNCTION public.superadmin_create_garage_owner(TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.superadmin_create_garage_owner(TEXT, TEXT, TEXT) TO authenticated;

-- -----------------------------------------------------------------------------
-- 6. Seed Step (Run AFTER creating superadmin@example.com in Supabase Auth)
-- -----------------------------------------------------------------------------
-- Links the provisioned Supabase Auth user (superadmin@example.com) into
-- public.superadmin_accounts if that Auth user already exists.
INSERT INTO public.superadmin_accounts (auth_user_id, email, full_name, is_active)
SELECT u.id, lower(u.email), 'Superadmin', true
  FROM auth.users u
 WHERE lower(u.email) = 'superadmin@example.com'
ON CONFLICT (auth_user_id) DO UPDATE
  SET is_active = true,
      updated_at = now();

COMMIT;
