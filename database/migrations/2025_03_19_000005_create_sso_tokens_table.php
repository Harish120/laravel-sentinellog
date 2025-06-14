<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class() extends Migration
{
    public function up(): void
    {
        Schema::create('sentinel_sso_tokens', function (Blueprint $table) {
            $table->id();
            $table->string('authenticatable_type')->nullable();
            $table->unsignedBigInteger('authenticatable_id')->nullable();
            $table->string('token', 64)->unique();
            $table->string('client_id')->index();
            $table->timestamp('issued_at')->useCurrent();
            $table->timestamp('expires_at');
            $table->timestamps();

            $table->index(['authenticatable_type', 'authenticatable_id'], 'sentinel_sso_tokens_auth_type_auth_id_idx');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sentinel_sso_tokens');
    }
};
