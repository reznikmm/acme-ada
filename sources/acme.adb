--  SPDX-FileCopyrightText: 2020 Max Reznik <reznikmm@gmail.com>
--
--  SPDX-License-Identifier: MIT
----------------------------------------------------------------

with Ada.Text_IO;
with Ada.Wide_Wide_Text_IO;

with GNAT.SHA256;

with AWS.Client;
with AWS.Default;
with AWS.Messages;
with AWS.Response;

with JWS;
with JWS.RS256;  pragma Unreferenced (JWS.RS256);  --  Enable RS256
with JWS.To_Base_64_URL;

with League.Calendars.ISO_8601;
with League.JSON.Arrays;
with League.JSON.Documents;
with League.JSON.Values;

package body ACME is

   function "+" (V : Wide_Wide_String) return League.Strings.Universal_String
     renames League.Strings.To_Universal_String;

   function "-" (V : Wide_Wide_String) return League.JSON.Values.JSON_Value
     is (League.JSON.Values.To_JSON_Value (+V));

   function "-" (V : League.Strings.Universal_String)
     return League.JSON.Values.JSON_Value
       is (League.JSON.Values.To_JSON_Value (V));

   User_Agent : constant String := AWS.Default.User_Agent &
     " acme-ada 0.0.1";

   procedure Get_Nonce
     (Self  : in out Context'Class;
      Nonce : out League.Strings.Universal_String);

   ------------------------
   -- Challenge_Complete --
   ------------------------

   procedure Challenge_Complete
     (Self          : in out Context'Class;
      Account_URL   : League.Strings.Universal_String;
      Private_Key   : League.Stream_Element_Vectors.Stream_Element_Vector;
      Challenge     : ACME.Challenge)
   is
      URL      : constant League.Strings.Universal_String := Challenge.URL;
      Nonce    : League.Strings.Universal_String;
      JWT      : JWS.JSON_Web_Signature;
      Header   : JWS.JOSE_Header;
      Result   : AWS.Response.Data;
   begin
      Self.Get_Nonce (Nonce);
      Ada.Wide_Wide_Text_IO.Put ("Nonce=");
      Ada.Wide_Wide_Text_IO.Put_Line (Nonce.To_Wide_Wide_String);

      Header.Set_Algorithm (+"RS256");
      Header.Insert (+"nonce", -Nonce);
      Header.Insert (+"url", -URL);
      Header.Insert (+"kid", -Account_URL);

      JWT.Create
        (Header  => Header,
         Payload => League.JSON.Objects.Empty_JSON_Object.
                      To_JSON_Document.To_JSON.To_Stream_Element_Array,
         Secret  => Private_Key.To_Stream_Element_Array);

      Ada.Wide_Wide_Text_IO.Put_Line
        (JWT.Flattened_Serialization.
           To_JSON_Document.To_JSON.To_Wide_Wide_String);

      Result := AWS.Client.Post
        (URL          => URL.To_UTF_8_String,
         Data         => JWT.Flattened_Serialization.
                           To_JSON_Document.To_JSON.To_UTF_8_String,
         Content_Type => "application/jose+json",
         User_Agent   => User_Agent);

      Ada.Text_IO.Put_Line (AWS.Response.Status_Code (Result)'Img);

      Ada.Text_IO.Put_Line
        (AWS.Response.Message_Body (Result));

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      if AWS.Response.Has_Header (Result, "Replay-Nonce") then
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;
   end Challenge_Complete;

   ----------------------
   -- Challenge_Status --
   ----------------------

   procedure Challenge_Status
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Challenge   : ACME.Challenge;
      Status      : out League.Strings.Universal_String)
   is
      URL      : constant League.Strings.Universal_String := Challenge.URL;
      Doc      : League.JSON.Documents.JSON_Document;
      Nonce    : League.Strings.Universal_String;
      JWT      : JWS.JSON_Web_Signature;
      Header   : JWS.JOSE_Header;
      Result   : AWS.Response.Data;
   begin
      Self.Get_Nonce (Nonce);
      Ada.Wide_Wide_Text_IO.Put ("Nonce=");
      Ada.Wide_Wide_Text_IO.Put_Line (Nonce.To_Wide_Wide_String);

      Header.Set_Algorithm (+"RS256");
      Header.Insert (+"nonce", -Nonce);
      Header.Insert (+"url", -URL);
      Header.Insert (+"kid", -Account_URL);

      JWT.Create
        (Header  => Header,
         Payload => (1 .. 0 => <>),
         Secret  => Private_Key.To_Stream_Element_Array);

      Result := AWS.Client.Post
        (URL          => URL.To_UTF_8_String,
         Data         => JWT.Flattened_Serialization.
                           To_JSON_Document.To_JSON.To_UTF_8_String,
         Content_Type => "application/jose+json",
         User_Agent   => User_Agent);

      Ada.Text_IO.Put_Line (AWS.Response.Status_Code (Result)'Img);

      Ada.Text_IO.Put_Line
        (AWS.Response.Message_Body (Result));

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      if AWS.Response.Has_Header (Result, "Replay-Nonce") then
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;

      Doc := League.JSON.Documents.From_JSON
        (AWS.Response.Message_Body (Result));

      Status := Doc.To_JSON_Object.Value (+"status").To_String;
   end Challenge_Status;

   --------------------
   -- Create_Account --
   --------------------

   procedure Create_Account
     (Self          : in out Context'Class;
      Public_Key    : League.JSON.Objects.JSON_Object;
      Private_Key   : League.Stream_Element_Vectors.Stream_Element_Vector;
      Contact       : League.String_Vectors.Universal_String_Vector;
      TOS_Agreed    : Boolean := True;
      Only_Existing : Boolean := False;
      Account_URL   : out League.Strings.Universal_String)
   is
      URL      : constant League.Strings.Universal_String :=
        Self.Directory.Value (+"newAccount").To_String;
      Account  : League.JSON.Objects.JSON_Object;
      Nonce    : League.Strings.Universal_String;
      Meta     : constant League.JSON.Objects.JSON_Object :=
        Self.Directory.Value (+"meta").To_Object;
      JWT      : JWS.JSON_Web_Signature;
      Header   : JWS.JOSE_Header;
      Result   : AWS.Response.Data;
   begin
      Self.Get_Nonce (Nonce);
      Ada.Wide_Wide_Text_IO.Put ("Nonce=");
      Ada.Wide_Wide_Text_IO.Put_Line (Nonce.To_Wide_Wide_String);

      if not Contact.Is_Empty then
         declare
            List : League.JSON.Arrays.JSON_Array;
         begin
            for J in 1 .. Contact.Length loop
               List.Append (-Contact (J));
            end loop;

            Account.Insert (+"contact", List.To_JSON_Value);
         end;
      end if;

      if Meta.Contains (+"termsOfService") then
         Account.Insert
           (+"termsOfServiceAgreed",
            League.JSON.Values.To_JSON_Value (TOS_Agreed));
      end if;

      if Only_Existing then
         Account.Insert
           (+"onlyReturnExisting",
            League.JSON.Values.To_JSON_Value (True));
      end if;

      Header.Set_Algorithm (+"RS256");
      Header.Insert (+"nonce", -Nonce);
      Header.Insert (+"url", -URL);
      Header.Insert (+"jwk", Public_Key.To_JSON_Value);

      JWT.Create
        (Header  => Header,
         Payload => Account.To_JSON_Document.To_JSON.To_Stream_Element_Array,
         Secret  => Private_Key.To_Stream_Element_Array);

      Result := AWS.Client.Post
        (URL          => URL.To_UTF_8_String,
         Data         => JWT.Flattened_Serialization.
                           To_JSON_Document.To_JSON.To_UTF_8_String,
         Content_Type => "application/jose+json",
         User_Agent   => User_Agent);

      Ada.Text_IO.Put_Line (AWS.Response.Status_Code (Result)'Img);

      Ada.Text_IO.Put_Line
        (AWS.Response.Message_Body (Result));

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      Account_URL := League.Strings.From_UTF_8_String
        (AWS.Response.Header (Result, "Location", 1));

      if AWS.Response.Has_Header (Result, "Replay-Nonce") then
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;
   end Create_Account;

   ------------------
   -- Create_Order --
   ------------------

   procedure Create_Order
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      DNS_Id_List : League.String_Vectors.Universal_String_Vector;
      Not_Before  : Optional_Date_Time := (Is_Set => False);
      Not_After   : Optional_Date_Time := (Is_Set => False);
      Auth_List   : out League.String_Vectors.Universal_String_Vector;
      Finalize    : out League.Strings.Universal_String;
      Order_URL   : out League.Strings.Universal_String)
   is
      Format   : constant League.Strings.Universal_String :=
        +"yyyy-MM-ddTHH:mm:ss+04:00Z";
      URL      : constant League.Strings.Universal_String :=
        Self.Directory.Value (+"newOrder").To_String;
      Doc      : League.JSON.Documents.JSON_Document;
      Order    : League.JSON.Objects.JSON_Object;
      Nonce    : League.Strings.Universal_String;
      JWT      : JWS.JSON_Web_Signature;
      Header   : JWS.JOSE_Header;
      Result   : AWS.Response.Data;
      List     : League.JSON.Arrays.JSON_Array;
   begin
      Self.Get_Nonce (Nonce);
      Ada.Wide_Wide_Text_IO.Put ("Nonce=");
      Ada.Wide_Wide_Text_IO.Put_Line (Nonce.To_Wide_Wide_String);

      Header.Set_Algorithm (+"RS256");
      Header.Insert (+"nonce", -Nonce);
      Header.Insert (+"url", -URL);
      Header.Insert (+"kid", -Account_URL);

      for J in 1 .. DNS_Id_List.Length loop
         declare
            DNS : League.JSON.Objects.JSON_Object;
         begin
            DNS.Insert (+"type", -"dns");
            DNS.Insert (+"value", -DNS_Id_List (J));
            List.Append (DNS.To_JSON_Value);
         end;
      end loop;

      Order.Insert (+"identifiers", List.To_JSON_Value);

      if Not_Before.Is_Set then
         Order.Insert
           (+"notBefore",
            -League.Calendars.ISO_8601.Image (Format, Not_Before.Value));
      end if;

      if Not_After.Is_Set then
         Order.Insert
           (+"notAfter",
            -League.Calendars.ISO_8601.Image (Format, Not_After.Value));
      end if;

      JWT.Create
        (Header  => Header,
         Payload => Order.To_JSON_Document.To_JSON.To_Stream_Element_Array,
         Secret  => Private_Key.To_Stream_Element_Array);

      Ada.Wide_Wide_Text_IO.Put_Line
        (JWT.Flattened_Serialization.
           To_JSON_Document.To_JSON.To_Wide_Wide_String);

      Result := AWS.Client.Post
        (URL          => URL.To_UTF_8_String,
         Data         => JWT.Flattened_Serialization.
                           To_JSON_Document.To_JSON.To_UTF_8_String,
         Content_Type => "application/jose+json",
         User_Agent   => User_Agent);

      Ada.Text_IO.Put_Line (AWS.Response.Status_Code (Result)'Img);

      Ada.Text_IO.Put_Line
        (AWS.Response.Message_Body (Result));

      Doc := League.JSON.Documents.From_JSON
        (AWS.Response.Message_Body (Result));

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      Order := Doc.To_JSON_Object;

      declare
         Vector : constant League.JSON.Arrays.JSON_Array :=
           Order.Value (+"authorizations").To_Array;
      begin
         for J in 1 .. Vector.Length loop
            Auth_List.Append (Vector (J).To_String);
         end loop;
      end;

      Finalize := Order.Value (+"finalize").To_String;

      Order_URL := League.Strings.From_UTF_8_String
        (AWS.Response.Header (Result, "Location", 1));

      if AWS.Response.Has_Header (Result, "Replay-Nonce") then
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;
   end Create_Order;

   --------------------
   -- Finalize_Order --
   --------------------

   procedure Finalize_Order
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Finalize    : League.Strings.Universal_String;
      CSR         : League.Stream_Element_Vectors.Stream_Element_Vector)
   is
      URL      : constant League.Strings.Universal_String := Finalize;
      Object    : League.JSON.Objects.JSON_Object;
      Nonce    : League.Strings.Universal_String;
      JWT      : JWS.JSON_Web_Signature;
      Header   : JWS.JOSE_Header;
      Result   : AWS.Response.Data;
   begin
      Self.Get_Nonce (Nonce);
      Ada.Wide_Wide_Text_IO.Put ("Nonce=");
      Ada.Wide_Wide_Text_IO.Put_Line (Nonce.To_Wide_Wide_String);

      Header.Set_Algorithm (+"RS256");
      Header.Insert (+"nonce", -Nonce);
      Header.Insert (+"url", -URL);
      Header.Insert (+"kid", -Account_URL);

      Object.Insert (+"csr", -JWS.To_Base_64_URL (CSR));

      JWT.Create
        (Header  => Header,
         Payload => Object.To_JSON_Document.To_JSON.To_Stream_Element_Array,
         Secret  => Private_Key.To_Stream_Element_Array);

      Ada.Wide_Wide_Text_IO.Put_Line
        (JWT.Flattened_Serialization.
           To_JSON_Document.To_JSON.To_Wide_Wide_String);

      Result := AWS.Client.Post
        (URL          => URL.To_UTF_8_String,
         Data         => JWT.Flattened_Serialization.
                           To_JSON_Document.To_JSON.To_UTF_8_String,
         Content_Type => "application/jose+json",
         User_Agent   => User_Agent);

      Ada.Text_IO.Put_Line (AWS.Response.Status_Code (Result)'Img);

      Ada.Text_IO.Put_Line
        (AWS.Response.Message_Body (Result));

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      if AWS.Response.Has_Header (Result, "Replay-Nonce") then
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;
   end Finalize_Order;

   -----------------------
   -- Get_Authorization --
   -----------------------

   procedure Get_Challenges
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Auth_URL    : League.Strings.Universal_String;
      HTTP        : out Challenge;
      DNS         : out Challenge)
   is
      URL      : constant League.Strings.Universal_String := Auth_URL;
      Doc      : League.JSON.Documents.JSON_Document;
      Auth     : League.JSON.Objects.JSON_Object;
      Nonce    : League.Strings.Universal_String;
      JWT      : JWS.JSON_Web_Signature;
      Header   : JWS.JOSE_Header;
      Result   : AWS.Response.Data;
   begin
      Self.Get_Nonce (Nonce);
      Ada.Wide_Wide_Text_IO.Put ("Nonce=");
      Ada.Wide_Wide_Text_IO.Put_Line (Nonce.To_Wide_Wide_String);

      Header.Set_Algorithm (+"RS256");
      Header.Insert (+"nonce", -Nonce);
      Header.Insert (+"url", -URL);
      Header.Insert (+"kid", -Account_URL);

      JWT.Create
        (Header  => Header,
         Payload => (1 .. 0 => <>),
         Secret  => Private_Key.To_Stream_Element_Array);

      Result := AWS.Client.Post
        (URL          => URL.To_UTF_8_String,
         Data         => JWT.Flattened_Serialization.
                           To_JSON_Document.To_JSON.To_UTF_8_String,
         Content_Type => "application/jose+json",
         User_Agent   => User_Agent);

      Ada.Text_IO.Put_Line (AWS.Response.Status_Code (Result)'Img);

      Ada.Text_IO.Put_Line
        (AWS.Response.Message_Body (Result));

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      Doc := League.JSON.Documents.From_JSON
        (AWS.Response.Message_Body (Result));

      Auth := Doc.To_JSON_Object;

      declare
         Vector : constant League.JSON.Arrays.JSON_Array :=
           Auth.Value (+"challenges").To_Array;
      begin
         for J in 1 .. Vector.Length loop
            declare
               use type League.Strings.Universal_String;
               Item : constant League.JSON.Objects.JSON_Object :=
                 Vector (J).To_Object;
            begin
               if Item.Value (+"type").To_String = +"http-01" then
                  HTTP.URL := Item.Value (+"url").To_String;
                  HTTP.Token := Item.Value (+"token").To_String;
               elsif Item.Value (+"type").To_String = +"dns-01" then
                  DNS.URL := Item.Value (+"url").To_String;
                  DNS.Token := Item.Value (+"token").To_String;
               end if;
            end;
         end loop;
      end;

      if AWS.Response.Has_Header (Result, "Replay-Nonce") then
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;
   end Get_Challenges;

   procedure Get_Certificate
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Certificate : League.Strings.Universal_String;
      Text        : out League.Strings.Universal_String)
   is
      URL      : constant League.Strings.Universal_String := Certificate;
      Nonce    : League.Strings.Universal_String;
      JWT      : JWS.JSON_Web_Signature;
      Header   : JWS.JOSE_Header;
      Headers  : AWS.Client.Header_List;
      Result   : AWS.Response.Data;
   begin
      Self.Get_Nonce (Nonce);

      Header.Set_Algorithm (+"RS256");
      Header.Insert (+"nonce", -Nonce);
      Header.Insert (+"url", -URL);
      Header.Insert (+"kid", -Account_URL);

      JWT.Create
        (Header  => Header,
         Payload => (1 .. 0 => <>),
         Secret  => Private_Key.To_Stream_Element_Array);

      Headers.Add ("Accept", "application/pem-certificate-chain");

      Result := AWS.Client.Post
        (URL          => URL.To_UTF_8_String,
         Data         => JWT.Flattened_Serialization.
                           To_JSON_Document.To_JSON.To_UTF_8_String,
         Content_Type => "application/jose+json",
         Headers      => Headers,
         User_Agent   => User_Agent);

      Ada.Text_IO.Put_Line (AWS.Response.Status_Code (Result)'Img);

      Ada.Text_IO.Put_Line
        (AWS.Response.Message_Body (Result));

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      if AWS.Response.Has_Header (Result, "Replay-Nonce") then
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;

      Text := League.Strings.From_UTF_8_String
        (AWS.Response.Message_Body (Result));
   end Get_Certificate;

   ---------------
   -- Get_Nonce --
   ---------------

   procedure Get_Nonce
     (Self  : in out Context'Class;
      Nonce : out League.Strings.Universal_String)
   is
      Result : AWS.Response.Data;
      URL    : League.Strings.Universal_String;
   begin
      if Self.Nonce.Is_Empty then
         URL := Self.Directory.Value (+"newNonce").To_String;

         Result := AWS.Client.Head
           (URL        => URL.To_UTF_8_String,
            User_Agent => User_Agent);

         pragma Assert (AWS.Response.Has_Header (Result, "Replay-Nonce"));
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;

      Nonce := Self.Nonce;
   end Get_Nonce;

   procedure Get_Order_Status
     (Self        : in out Context'Class;
      Account_URL : League.Strings.Universal_String;
      Private_Key : League.Stream_Element_Vectors.Stream_Element_Vector;
      Order_URL   : League.Strings.Universal_String;
      Certificate : out League.Strings.Universal_String;
      Status      : out League.Strings.Universal_String)
   is
      URL      : constant League.Strings.Universal_String := Order_URL;
      Doc      : League.JSON.Documents.JSON_Document;
      Nonce    : League.Strings.Universal_String;
      JWT      : JWS.JSON_Web_Signature;
      Header   : JWS.JOSE_Header;
      Result   : AWS.Response.Data;
   begin
      Self.Get_Nonce (Nonce);

      Header.Set_Algorithm (+"RS256");
      Header.Insert (+"nonce", -Nonce);
      Header.Insert (+"url", -URL);
      Header.Insert (+"kid", -Account_URL);

      JWT.Create
        (Header  => Header,
         Payload => (1 .. 0 => <>),
         Secret  => Private_Key.To_Stream_Element_Array);

      Result := AWS.Client.Post
        (URL          => URL.To_UTF_8_String,
         Data         => JWT.Flattened_Serialization.
                           To_JSON_Document.To_JSON.To_UTF_8_String,
         Content_Type => "application/jose+json",
         User_Agent   => User_Agent);

      Ada.Text_IO.Put_Line (AWS.Response.Status_Code (Result)'Img);

      Ada.Text_IO.Put_Line
        (AWS.Response.Message_Body (Result));

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      if AWS.Response.Has_Header (Result, "Replay-Nonce") then
         Self.Nonce := League.Strings.From_UTF_8_String
           (AWS.Response.Header (Result, "Replay-Nonce", 1));
      end if;

      Doc := League.JSON.Documents.From_JSON
        (AWS.Response.Message_Body (Result));

      Status := Doc.To_JSON_Object.Value (+"status").To_String;
      Certificate := Doc.To_JSON_Object.Value (+"certificate").To_String;
   end Get_Order_Status;

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize
     (Self             : in out Context'Class;
      Directory_URL    : League.Strings.Universal_String;
      Terms_Of_Service : out League.Strings.Universal_String)
   is
      Doc    : League.JSON.Documents.JSON_Document;
      Meta   : League.JSON.Objects.JSON_Object;
      Result : AWS.Response.Data;
      URL    : constant League.Strings.Universal_String := Directory_URL;
   begin
      Result := AWS.Client.Get
        (URL                => URL.To_UTF_8_String,
         Follow_Redirection => True,
         User_Agent         => User_Agent);

      pragma Assert
        (AWS.Response.Status_Code (Result) in AWS.Messages.Success);

      Doc := League.JSON.Documents.From_JSON
        (AWS.Response.Message_Body (Result));
      Self.Directory := Doc.To_JSON_Object;

      pragma Assert (Self.Directory.Contains (+"newNonce"));
      pragma Assert (Self.Directory.Contains (+"newAccount"));
      pragma Assert (Self.Directory.Contains (+"newOrder"));
      pragma Assert (Self.Directory.Contains (+"revokeCert"));
      pragma Assert (Self.Directory.Contains (+"keyChange"));

      Meta := Self.Directory.Value (+"meta").To_Object;
      Terms_Of_Service := Meta.Value (+"termsOfService").To_String;
   end Initialize;

   -----------------------
   -- Key_Authorization --
   -----------------------

   function Key_Authorization
     (Token      : League.Strings.Universal_String;
      Public_Key : League.JSON.Objects.JSON_Object)
        return League.Strings.Universal_String
   is
      SHA256 : constant GNAT.SHA256.Binary_Message_Digest :=
        GNAT.SHA256.Digest (JWS.Thumbprint (Public_Key));

      Vector : League.Stream_Element_Vectors.Stream_Element_Vector;
      Result : League.Strings.Universal_String;
   begin
      Vector.Append (SHA256);

      Result.Append (Token);
      Result.Append ('.');
      Result.Append (JWS.To_Base_64_URL (Vector));

      return Result;
   end Key_Authorization;

end ACME;
